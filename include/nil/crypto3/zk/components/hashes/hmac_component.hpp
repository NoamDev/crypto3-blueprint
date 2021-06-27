#ifndef CRYPTO3_ZK_HMAC_COMPONENT_HPP
#define CRYPTO3_ZK_HMAC_COMPONENT_HPP

#include<nil/crypto3/zk/components/basic_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename FieldType, typename Hash1, typename Hash2=Hash1>
                class hmac_component : component<FieldType> {
                    static_assert(std::is_same<typename Hash1::hash_value_type, std::vector<bool>>::value);
                public:
                    blueprint_variable_vector<FieldType> padded_key;
                    blueprint_variable_vector<FieldType> key_xor_ipad;
                    blueprint_variable_vector<FieldType> key_xor_opad;
                    std::shared_ptr<Hash1> hash1;
                    std::shared_ptr<digest_variable<FieldType>> hash1_result;
                    std::shared_ptr<Hash2> hash2;
                    blueprint_variable<FieldType> zero;
                public:
                    hmac_component(blueprint<FieldType> &bp,
                                    const block_variable<FieldType> &key,
                                    const block_variable<FieldType> &message,
                                   const typename Hash2::hash_variable_type &output): component<FieldType>(bp) {
                        assert(Hash1::get_block_len() == Hash2::get_block_len());
                        assert(Hash1::get_block_len() == 0 || key.block_size <= Hash1::get_block_len());
                        
                        std::size_t padded_key_size = ( Hash1::get_block_len() != 0 ? Hash1::get_block_len() : key.block_size);
                        zero.allocate(bp);
                        blueprint_variable_vector<FieldType> padding(padded_key_size - key.block_size, zero);
                        padded_key.reserve(padded_key_size);
                        padded_key.insert(padded_key.end(), key.bits.begin(), key.bits.end());
                        padded_key.insert(padded_key.end(), padding.begin(), padding.end());
                        
                        key_xor_ipad.allocate(bp, padded_key_size);
                        key_xor_opad.allocate(bp, padded_key_size);
                        
                        block_variable<FieldType> iblock(bp, {key_xor_ipad, message.bits});
                        hash1_result.reset(new digest_variable<FieldType>(bp, Hash1::get_digest_len()));
                        hash1.reset(new Hash1(bp, iblock.block_size, iblock, *hash1_result));

                        block_variable<FieldType> oblock(bp, {key_xor_opad, hash1_result->bits});
                        hash2.reset(new Hash2(bp, oblock.block_size, oblock, output));
                    }

                    void generate_r1cs_constraints() {
                        generate_r1cs_equals_const_constraint<FieldType>(this->bp, zero, FieldType::value_type::zero());
                        generate_xor_constraints(0x36, padded_key, key_xor_ipad);
                        generate_xor_constraints(0x5c, padded_key, key_xor_opad);
                        hash1->generate_r1cs_constraints();
                        hash2->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->bp.val(zero) = FieldType::value_type::zero();
                        generate_xor_witness(0x36, padded_key, key_xor_ipad);
                        generate_xor_witness(0x5c, padded_key, key_xor_opad);
                        hash1->generate_r1cs_witness();
                        hash2->generate_r1cs_witness();
                    }

                private:
                    void generate_xor_constraints(std::uint8_t xor_pad,
                                                  const blueprint_variable_vector<FieldType> &input,
                                                  const blueprint_variable_vector<FieldType> &output) {
                        assert(input.size() == output.size());
                        std::vector<bool> xor_pad_bits(8);
                        for(std::size_t i = 0; i < 8; ++i) {
                            xor_pad_bits[8-i] = xor_pad&(1<<i);
                        }
                        for(std::size_t i = 0; i < input.size(); ++i) {
                            // x xor 0 = x
                            // x xor 1 = !x
                            if(!xor_pad_bits[i%8]) {
                                this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(1, input[i], output[i]));
                            } else {
                                this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(1, 1-input[i], output[i]));
                            }
                        }
                    }

                    void generate_xor_witness(std::uint8_t xor_pad,
                                                  const blueprint_variable_vector<FieldType> &input,
                                                  const blueprint_variable_vector<FieldType> &output) {
                        assert(input.size() == output.size());
                        std::vector<bool> xor_pad_bits(8);
                        for(std::size_t i = 0; i < 8; ++i) {
                            xor_pad_bits[8-i] = xor_pad&(1<<i);
                        }

                        for(std::size_t i = 0; i < input.size(); ++i) {
                            // x xor 0 = x
                            // x xor 1 = !x
                            if(!xor_pad_bits[i%8]) {
                                this->bp.val(output[i]) = this->bp.val(input[i]);
                            } else {
                                this->bp.val(output[i]) = (this->bp.val(input[i]) == 0 ? 1 : 0);
                            }
                        }
                    }
                };
            }    // namespace components
        }            // namespace zk
    }                // namespace crypto3
} 

#endif    // CRYPTO3_ZK_HMAC_COMPONENT_HPP
