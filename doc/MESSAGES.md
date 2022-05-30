# List of supported messages and their descriptors

This list contains a number of messages that ledger could assemble and display critical information (hints) about what's this transaction is about.

| ID | Message | Description |
| --- | --- | --- |
| 0x00 | Message with Comment| Typical transaction with a comment|
| 0x01 | Upgrade | Message for upgrading code of a contract |
| 0x02 | Deposit | Whales Nominators deposit command |
| 0x03 | Withdraw | Whales Nominators withdraw command |
| *0x04 | Transfer ownership | Universal message for transfering ownership of the contract |
| *0x05 | Create Proposal | Universal message for creating DAO proposal |
| *0x06 | Vote | Universal message for voting YES/NO/ABSTAIN for a proposal in DAO |
| *0x07 | Execute proposal | Universal message for executing proposal in DAO |
| *0x08 | Abort proposal | Universal message for aborting proposal in DAO |

# 0x00: Message with comment

This is just a usual transaction with a comment, but it have it's limitations:
* Only ASCII-printable symbols are supported
* 120 symbols max

### TL-B
```
message#00000000 text: string = MsgBody;
```

### Hints
| Value | Length | Description |
| --- | --- | --- |
| `message` | `var` | ASCII-only message |

# 0x01: Upgrade
Universal code upgrade message

### TL-B
```
upgrade#dbfaf817 code: ^Cell = MsgBody;
upgrade#dbfaf817 query_id:uint64 code: ^Cell = MsgBody;
upgrade#dbfaf817 gas_limit:Coins code: ^Cell = MsgBody;
upgrade#dbfaf817 query_id:uint64 gas_limit:Coins code: ^Cell = MsgBody;
```

### Hints
| Value | Length | Description |
| --- | --- | --- |
| `has_query_id` | 1 | if query id exist |
| `query_id` | 8 | query id if exist |
| `has_gas_limit`| 1 | gas_limit if exist |
| `gas_limit`| 8 | gas_limit if exist |
| `code_ref` | 34 | Cell Reference of a Code hash to be shown to user in Base64 format |

# 0x02: Deposit
Deposit to a TON Whales staking pool

### TL-B
```
deposit#7bcd1fef = MsgBody;
deposit#7bcd1fef gas_limit:Coins = MsgBody;
deposit#7bcd1fef query_id:uint64 = MsgBody;
deposit#7bcd1fef query_id:uint64 gas_limit:Coins = MsgBody;
```

### Hints
| Value | Length | Description |
| --- | --- | --- |
| `has_query_id` | 1 | if query id exist |
| `query_id` | 8 | query id if exist |
| `has_gas_limit`| 1 | gas_limit if exist |
| `gas_limit`| 8 | gas_limit if exist |

# 0x03: Withdraw
Withdraw to a TON Whales staking pool

### TL-B
```
withdraw#da803efd amount:Coins = MsgBody;
withdraw#da803efd query_id:uint64 amount:Coins = MsgBody;
withdraw#da803efd gas_limit:Coins amount:Coins = MsgBody;
withdraw#da803efd query_id:uint64 gas_limit:Coins amount:Coins = MsgBody;
```

### Hints
| Value | Length | Description |
| --- | --- | --- |
| `has_query_id` | 1 | if query id exist |
| `query_id` | 8 | query id |
| `has_query_id` | 1 | if query id exist |
| `gas_limit`| 8 | gas_limit |
| `amount`| 8 | amount |