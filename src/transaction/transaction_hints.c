#include <string.h>
#include <stdio.h>

#include "transaction_hints.h"

#include "../common/buffer.h"
#include "../common/base64.h"
#include "../common/format_bigint.h"
#include "../common/format_address.h"
#include "../common/encoding.h"
#include "../constants.h"
#include "deserialize.h"
#include "../common/hints.h"
#include "../common/bits.h"
#include "../common/cell.h"

#define SAFE(RES)     \
    if (!RES) {       \
        return false; \
    }

#define CHECK_END()               \
    if (buf.offset != buf.size) { \
        return false;             \
    }

bool process_hints(transaction_t* tx) {
    // Default title
    snprintf(tx->title, sizeof(tx->title), "Transaction");

    // No payload
    if (!tx->has_payload) {
        snprintf(tx->title, sizeof(tx->title), "Transfer");
        tx->is_blind = false;
        return true;
    }
    // No hints
    if (!tx->has_hints) {
        tx->is_blind = true;
        return true;
    }

    // Default state
    tx->is_blind = true;
    CellRef_t cell;
    BitString_t bits;
    bool hasCell = false;
    bool tmp = false;
    tx->hints.hints_count = 0;
    buffer_t buf = {.ptr = tx->hints_data, .size = tx->hints_len, .offset = 0};

    //
    // Comment
    //

    if (tx->hints_type == TRANSACTION_COMMENT) {
        // Max size of a comment is 120 symbols
        if (tx->hints_len > MAX_MEMO_LEN) {
            return false;
        }

        // Check ASCII
        if (!check_ascii(tx->hints_data, tx->hints_len)) {
            return false;
        }

        // Build cell
        BitString_init(&bits);
        BitString_storeUint(&bits, 0, 32);
        BitString_storeBuffer(&bits, tx->hints_data, tx->hints_len);
        SAFE(hash_Cell(&bits, NULL, 0, &cell));
        hasCell = true;

        // Change title of operation
        snprintf(tx->title, sizeof(tx->title), "Transfer");

        // Add code hints
        add_hint_text(&tx->hints, "Comment", (char*) tx->hints_data, tx->hints_len);
    }

    if (tx->hints_type == TRANSACTION_TRANSFER_JETTON ||
        tx->hints_type == TRANSACTION_TRANSFER_NFT) {
        int ref_count = 0;
        CellRef_t refs[2] = {0};

        BitString_init(&bits);
        BitString_storeUint(&bits,
                            tx->hints_type == TRANSACTION_TRANSFER_JETTON ? 0x0f8a7ea5 : 0x5fcc3d14,
                            32);

        SAFE(buffer_read_bool(&buf, &tmp));
        if (tmp) {
            uint64_t query_id;
            SAFE(buffer_read_u64(&buf, &query_id, BE));
            BitString_storeUint(&bits, query_id, 64);
        } else {
            BitString_storeUint(&bits, 0, 64);
        }

        if (tx->hints_type == TRANSACTION_TRANSFER_JETTON) {
            uint8_t amount_size;
            uint8_t amount_buf[MAX_VALUE_BYTES_LEN];
            SAFE(buffer_read_varuint(&buf, &amount_size, amount_buf, MAX_VALUE_BYTES_LEN));
            BitString_storeCoinsBuf(&bits, amount_buf, amount_size);
            uint8_t amount_decimals;
            SAFE(buffer_read_u8(&buf, &amount_decimals));
            uint8_t ticker_size;
            SAFE(buffer_read_u8(&buf, &ticker_size));
            if (ticker_size > MAX_TICKER_LEN) {
                return false;
            }
            uint8_t ticker[MAX_TICKER_LEN + 1];
            SAFE(buffer_read_buffer(&buf, ticker, ticker_size));
            ticker[ticker_size] = 0;
            if (!check_ascii(ticker, ticker_size)) {
                return false;
            }

            add_hint_amount(&tx->hints,
                            "Jetton amount",
                            (char*) ticker,
                            amount_buf,
                            amount_size,
                            amount_decimals);
        }

        address_t destination;
        SAFE(buffer_read_address(&buf, &destination));
        BitString_storeAddress(&bits, destination.chain, destination.hash);

        add_hint_address(
            &tx->hints,
            tx->hints_type == TRANSACTION_TRANSFER_JETTON ? "Send jetton to" : "New owner",
            destination);

        address_t response;
        SAFE(buffer_read_address(&buf, &response));
        BitString_storeAddress(&bits, response.chain, response.hash);

        add_hint_address(&tx->hints, "Send excess to", response);

        // custom payload
        SAFE(buffer_read_bool(&buf, &tmp));
        if (tmp) {
            SAFE(buffer_read_cell_ref(&buf, &refs[ref_count]));

            add_hint_hash(&tx->hints, "Custom payload", refs[ref_count].hash);

            BitString_storeBit(&bits, 1);
            ref_count++;
        } else {
            BitString_storeBit(&bits, 0);
        }

        uint8_t fwd_amount_size;
        uint8_t fwd_amount_buf[MAX_VALUE_BYTES_LEN];
        SAFE(buffer_read_varuint(&buf, &fwd_amount_size, fwd_amount_buf, MAX_VALUE_BYTES_LEN));
        BitString_storeCoinsBuf(&bits, fwd_amount_buf, fwd_amount_size);

        add_hint_amount(&tx->hints,
                        "Forward amount",
                        "TON",
                        fwd_amount_buf,
                        fwd_amount_size,
                        EXPONENT_SMALLEST_UNIT);

        // forward payload
        SAFE(buffer_read_bool(&buf, &tmp));
        if (tmp) {
            SAFE(buffer_read_cell_ref(&buf, &refs[ref_count]));

            add_hint_hash(&tx->hints, "Forward payload", refs[ref_count].hash);

            BitString_storeBit(&bits, 1);
            ref_count++;
        } else {
            BitString_storeBit(&bits, 0);
        }

        CHECK_END();

        // Build cell
        SAFE(hash_Cell(&bits, refs, ref_count, &cell));
        hasCell = true;

        // Operation
        snprintf(
            tx->title,
            sizeof(tx->title),
            tx->hints_type == TRANSACTION_TRANSFER_JETTON ? "Transfer jetton" : "Transfer NFT");
    }

    // Check hash
    if (hasCell) {
        if (memcmp(cell.hash, tx->payload.hash, HASH_LEN) != 0) {
            return false;
        }
        tx->is_blind = false;
    }

    return true;
}