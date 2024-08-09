/*****************************************************************************
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>  // uint*_t
#include <stddef.h>  // size_t

uint64_t read_u48_be(const uint8_t *ptr, size_t offset) {
    return (uint64_t) ptr[offset + 0] << 40 |  //
           (uint64_t) ptr[offset + 1] << 32 |  //
           (uint64_t) ptr[offset + 2] << 24 |  //
           (uint64_t) ptr[offset + 3] << 16 |  //
           (uint64_t) ptr[offset + 4] << 8 |   //
           (uint64_t) ptr[offset + 5] << 0;
}

uint64_t read_u48_le(const uint8_t *ptr, size_t offset) {
    return (uint64_t) ptr[offset + 0] << 0 |   //
           (uint64_t) ptr[offset + 1] << 8 |   //
           (uint64_t) ptr[offset + 2] << 16 |  //
           (uint64_t) ptr[offset + 3] << 24 |  //
           (uint64_t) ptr[offset + 4] << 32 |  //
           (uint64_t) ptr[offset + 5] << 40;
}