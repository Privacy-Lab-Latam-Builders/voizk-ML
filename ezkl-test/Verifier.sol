// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    DELTA = 4131629893567559867359510883348571134090853742863529169391034518566172092834;
    uint256 internal constant        R = 21888242871839275222246405745257275088548364400416034343698204186575808495617; 
    uint256 internal constant    PROOF_LEN_CPTR = 0x6014f51944;
    uint256 internal constant        PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x1324;
    uint256 internal constant     INSTANCE_CPTR = 0x1344;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x0824;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x09e4;

    uint256 internal constant                VK_MPTR = 0x05a0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x05a0;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x05c0;
    uint256 internal constant                 K_MPTR = 0x05e0;
    uint256 internal constant             N_INV_MPTR = 0x0600;
    uint256 internal constant             OMEGA_MPTR = 0x0620;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0640;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0660;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0680;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x06a0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x06c0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x06e0;
    uint256 internal constant              G1_X_MPTR = 0x0700;
    uint256 internal constant              G1_Y_MPTR = 0x0720;
    uint256 internal constant            G2_X_1_MPTR = 0x0740;
    uint256 internal constant            G2_X_2_MPTR = 0x0760;
    uint256 internal constant            G2_Y_1_MPTR = 0x0780;
    uint256 internal constant            G2_Y_2_MPTR = 0x07a0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x07c0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x07e0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0800;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0820;

    uint256 internal constant CHALLENGE_MPTR = 0x0dc0;

    uint256 internal constant THETA_MPTR = 0x0dc0;
    uint256 internal constant  BETA_MPTR = 0x0de0;
    uint256 internal constant GAMMA_MPTR = 0x0e00;
    uint256 internal constant     Y_MPTR = 0x0e20;
    uint256 internal constant     X_MPTR = 0x0e40;
    uint256 internal constant  ZETA_MPTR = 0x0e60;
    uint256 internal constant    NU_MPTR = 0x0e80;
    uint256 internal constant    MU_MPTR = 0x0ea0;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x0ec0;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x0ee0;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x0f00;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x0f20;
    uint256 internal constant             X_N_MPTR = 0x0f40;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x0f60;
    uint256 internal constant          L_LAST_MPTR = 0x0f80;
    uint256 internal constant         L_BLIND_MPTR = 0x0fa0;
    uint256 internal constant             L_0_MPTR = 0x0fc0;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x0fe0;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x1000;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x1020;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1040;
    uint256 internal constant          R_EVAL_MPTR = 0x1060;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x1080;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x10a0;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x10c0;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x10e0;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), R)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), R)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(R, 2))
                mstore(add(gp_mptr, 0xa0), R)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), R)
                    all_inv := mulmod(all_inv, mload(mptr), R)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), R)
                let inv_second := mulmod(all_inv, mload(first_mptr), R)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field 

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x05a0, 0x1c2878c8ffded75b5d6b81fce41fe04a1e0ddf64790f74eb1c1720506927b60b) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000000003) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x12c0, calldataload(sub(PROOF_LEN_CPTR, 0x6014F51900))))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0180) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x02c0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0380) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0200) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0880) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x05a0, 0x1c2878c8ffded75b5d6b81fce41fe04a1e0ddf64790f74eb1c1720506927b60b) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000000003) // num_instances
                mstore(0x05e0, 0x000000000000000000000000000000000000000000000000000000000000000c) // k
                mstore(0x0600, 0x3061482dfa038d0fb5b4c0b226194047a2616509f531d4fa3acdb77496c10001) // n_inv
                mstore(0x0620, 0x2f6122bbf1d35fdaa9953f60087a423238aa810773efee2a251aa6161f2e6ee6) // omega
                mstore(0x0640, 0x179c2392139def1b24f4e92b4bfba20a0fa885cb6bfc2f2cb92790e00237d0c0) // omega_inv
                mstore(0x0660, 0x28771071ab1633014eae27cfc16d5ebe08a8fe2fc9e85044e4a45f82c14cd825) // omega_inv_to_l
                mstore(0x0680, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x06a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x06c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x06e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0700, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0720, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0740, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0760, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0780, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x07a0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x07c0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
                mstore(0x07e0, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
                mstore(0x0800, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
                mstore(0x0820, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
                mstore(0x0840, 0x2fc2ccbb19e23d25bd6101a44413851459664030b03b9e5e339b17ee8e5a751d) // fixed_comms[0].x
                mstore(0x0860, 0x169876e8c2862992c48e9e3081f44eb918cf1d7c014275a5588d6a6f4df5db32) // fixed_comms[0].y
                mstore(0x0880, 0x052669693850a7b66ce748a9357cea4af3c120d45adc96a3f51c21dce2006e09) // fixed_comms[1].x
                mstore(0x08a0, 0x284ec1e9db21d06f5557731d473e4699dc02210cc9a7bd08ffab5f93e861715b) // fixed_comms[1].y
                mstore(0x08c0, 0x02f29b2d7b17de09a06be3ccba7370d4610d4d468345411ed121dfb3be0c88b9) // fixed_comms[2].x
                mstore(0x08e0, 0x09e16cd5997d09e56cbe0603cab42fb471b6a35a3dec71b52990f97645b1be3e) // fixed_comms[2].y
                mstore(0x0900, 0x13bce136eb7fad9fb32615163b0c799c25d07b2ef87aaced9fa33ad185760dec) // fixed_comms[3].x
                mstore(0x0920, 0x02ed884305ec8bfb2edcd14210d8cf8900f549c79efe0b7f90fcdb82b493c5ab) // fixed_comms[3].y
                mstore(0x0940, 0x14eda040a7c41565bb3558d3382d695cc94af002861aa147eca8a11fa2750a50) // fixed_comms[4].x
                mstore(0x0960, 0x136b1743d764af07be59985759483c7920b5451f25b3b27c9944eb6faa24c6b1) // fixed_comms[4].y
                mstore(0x0980, 0x264beb6f2563ff0fdd25493d495c20f2a58300f507acb41b4c9253b8c240ccc3) // fixed_comms[5].x
                mstore(0x09a0, 0x22a5c1012fd6b8a37e8ac9621127aa103ac2e884d20a5c6d4e2bf3d16e796595) // fixed_comms[5].y
                mstore(0x09c0, 0x26b6099cbe3fffa074e8a76fd31d5e10aabd6b396406b27ef018db6c759c349b) // fixed_comms[6].x
                mstore(0x09e0, 0x22f345155662caab46494b6eed2d7573aa44f000f5a3759899f4bc0847e13e01) // fixed_comms[6].y
                mstore(0x0a00, 0x104322672515b1c199d772d9e0929beacd31b075eb26a81368f1be40ede5933e) // fixed_comms[7].x
                mstore(0x0a20, 0x254ba3c0c92deba0cc0d265eab23dbc3f3ffc2ca6ae4d7376892f34a34aace5e) // fixed_comms[7].y
                mstore(0x0a40, 0x2e2f757f141c90e3d488ec6d1a9ceadedda7c745ea8e8b6f3327fd5083c090de) // fixed_comms[8].x
                mstore(0x0a60, 0x0b3b5e29f47251e26dc63ba82b2f417357d637cf9db75383e6c024c09acd732e) // fixed_comms[8].y
                mstore(0x0a80, 0x0b4b3d7e3f0db7a331745e2e424bb9738d5ef592ab00d46f514f37d9a84f5f92) // fixed_comms[9].x
                mstore(0x0aa0, 0x1ed7f0b048058dbaff5224528ad7504bb736480471fa8d48aa141ad6a22314ea) // fixed_comms[9].y
                mstore(0x0ac0, 0x0d2b2cb21bea59f92fca10e672b66352990e5ae04d9f889f15462698148550cc) // fixed_comms[10].x
                mstore(0x0ae0, 0x14195ac373fdb7ffb70c246a632b8628b74a4a617e4978af123839116f9cc6a1) // fixed_comms[10].y
                mstore(0x0b00, 0x28165cef1cf63868b318b9add26a62163b52411132f3f6d1267fbd682eaaf2fd) // fixed_comms[11].x
                mstore(0x0b20, 0x04951f5c89054782c01269358e7a5a606a60d29ce23dc5c15b03d378ea3d0d5f) // fixed_comms[11].y
                mstore(0x0b40, 0x077cf6267dd18d409ac7fc83fdb035c0d4fc82cba2c05d1deabd6d24d507c2cc) // fixed_comms[12].x
                mstore(0x0b60, 0x2dca17ed808dd4a3840fec0d25ed6a4a663f0b4aa191b3624c1832f5e80128f7) // fixed_comms[12].y
                mstore(0x0b80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].x
                mstore(0x0ba0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].y
                mstore(0x0bc0, 0x2c8de08012c9d69aa8eccd462574165dd5ead9f20bbe05262c51427b95033263) // permutation_comms[0].x
                mstore(0x0be0, 0x18352419b182d7798927d820eca1e8512ac4de6a7a54ee955f27c673fb43891b) // permutation_comms[0].y
                mstore(0x0c00, 0x0b11202bf5179364c482a622f0102de114b2bfb2714f7e7682490419f030b9e7) // permutation_comms[1].x
                mstore(0x0c20, 0x1463fa981bb03a60589885269d2ee81de29a8362d82028426d8d88de59c4e2ee) // permutation_comms[1].y
                mstore(0x0c40, 0x070fd14739d496c252fe3e6fd1840f11d5d80f935cf005b41fda861d56b9f177) // permutation_comms[2].x
                mstore(0x0c60, 0x1caf122d69b81ecc0cc9310acb17e8508126a70bcca40391a8383ab77083f7c2) // permutation_comms[2].y
                mstore(0x0c80, 0x1c54e4c8dc2e5c69d546fdaa4ebee909600d4509c26ce9c0a22275716e06ad5d) // permutation_comms[3].x
                mstore(0x0ca0, 0x0a0cdd95cf7950e0a372baadf69b91a0586dcfdbf74fdffffcda26da74cd9212) // permutation_comms[3].y
                mstore(0x0cc0, 0x166dc5b7e7c91ac87c7cfed36c52773fdac6b45da5812bb0e96118fb4195c643) // permutation_comms[4].x
                mstore(0x0ce0, 0x2dd829f7133f07c154c8206b4dff9a17d074261fcb72805a6b7294db7464eb72) // permutation_comms[4].y
                mstore(0x0d00, 0x26eb7a8d53f5734889f182fbd3bb5b9b87a284e50c94f2d73bc19629d496acfa) // permutation_comms[5].x
                mstore(0x0d20, 0x03dc23160c83c512659630723f684c524c597c5653f33e0ed09c2b1c3cccb668) // permutation_comms[5].y
                mstore(0x0d40, 0x1d075b98deba0bcec9abad7d3c588acb65975fccfa028dd0ef7c58ee7260b489) // permutation_comms[6].x
                mstore(0x0d60, 0x0d1a71cbda70760a0ae1ac7bc39c69173be8075afeadb527d70ceda7ea64a40f) // permutation_comms[6].y
                mstore(0x0d80, 0x170b758c53e24153299324a3f3405ad7a194da01b2c1cdf3e620f724e975749a) // permutation_comms[7].x
                mstore(0x0da0, 0x0b20add3e175007b847472d5c377918d5a7251b5e41bfa27768e23e03bfdc4f4) // permutation_comms[7].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20))

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let y := mload(Y_MPTR)
                {
                    let f_11 := calldataload(0x0c64)
                    let var0 := 0x2
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let var16 := 0x7
                    let var17 := addmod(var16, var1, R)
                    let var18 := mulmod(var15, var17, R)
                    let a_4 := calldataload(0x0aa4)
                    let a_0 := calldataload(0x0a24)
                    let a_2 := calldataload(0x0a64)
                    let var19 := addmod(a_0, a_2, R)
                    let var20 := sub(R, var19)
                    let var21 := addmod(a_4, var20, R)
                    let var22 := mulmod(var18, var21, R)
                    quotient_eval_numer := var22
                }
                {
                    let f_12 := calldataload(0x0c84)
                    let var0 := 0x2
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_5 := calldataload(0x0ac4)
                    let a_1 := calldataload(0x0a44)
                    let a_3 := calldataload(0x0a84)
                    let var16 := addmod(a_1, a_3, R)
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_5, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_11 := calldataload(0x0c64)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let var16 := 0x7
                    let var17 := addmod(var16, var1, R)
                    let var18 := mulmod(var15, var17, R)
                    let a_4 := calldataload(0x0aa4)
                    let a_0 := calldataload(0x0a24)
                    let a_2 := calldataload(0x0a64)
                    let var19 := mulmod(a_0, a_2, R)
                    let var20 := sub(R, var19)
                    let var21 := addmod(a_4, var20, R)
                    let var22 := mulmod(var18, var21, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var22, r)
                }
                {
                    let f_12 := calldataload(0x0c84)
                    let var0 := 0x1
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_5 := calldataload(0x0ac4)
                    let a_1 := calldataload(0x0a44)
                    let a_3 := calldataload(0x0a84)
                    let var16 := mulmod(a_1, a_3, R)
                    let var17 := sub(R, var16)
                    let var18 := addmod(a_5, var17, R)
                    let var19 := mulmod(var15, var18, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_11 := calldataload(0x0c64)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let var16 := 0x7
                    let var17 := addmod(var16, var1, R)
                    let var18 := mulmod(var15, var17, R)
                    let a_4 := calldataload(0x0aa4)
                    let a_0 := calldataload(0x0a24)
                    let a_2 := calldataload(0x0a64)
                    let var19 := sub(R, a_2)
                    let var20 := addmod(a_0, var19, R)
                    let var21 := sub(R, var20)
                    let var22 := addmod(a_4, var21, R)
                    let var23 := mulmod(var18, var22, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var23, r)
                }
                {
                    let f_12 := calldataload(0x0c84)
                    let var0 := 0x1
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_5 := calldataload(0x0ac4)
                    let a_1 := calldataload(0x0a44)
                    let a_3 := calldataload(0x0a84)
                    let var16 := sub(R, a_3)
                    let var17 := addmod(a_1, var16, R)
                    let var18 := sub(R, var17)
                    let var19 := addmod(a_5, var18, R)
                    let var20 := mulmod(var15, var19, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var20, r)
                }
                {
                    let f_11 := calldataload(0x0c64)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let var16 := 0x7
                    let var17 := addmod(var16, var1, R)
                    let var18 := mulmod(var15, var17, R)
                    let a_4 := calldataload(0x0aa4)
                    let var19 := sub(R, var0)
                    let var20 := addmod(a_4, var19, R)
                    let var21 := mulmod(a_4, var20, R)
                    let var22 := mulmod(var18, var21, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var22, r)
                }
                {
                    let f_11 := calldataload(0x0c64)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let var16 := 0x7
                    let var17 := addmod(var16, var1, R)
                    let var18 := mulmod(var15, var17, R)
                    let a_5 := calldataload(0x0ac4)
                    let var19 := sub(R, var0)
                    let var20 := addmod(a_5, var19, R)
                    let var21 := mulmod(a_5, var20, R)
                    let var22 := mulmod(var18, var21, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var22, r)
                }
                {
                    let f_11 := calldataload(0x0c64)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x5
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let var16 := 0x6
                    let var17 := addmod(var16, var1, R)
                    let var18 := mulmod(var15, var17, R)
                    let a_4 := calldataload(0x0aa4)
                    let a_4_prev_1 := calldataload(0x0ae4)
                    let var19 := 0x0
                    let a_0 := calldataload(0x0a24)
                    let a_2 := calldataload(0x0a64)
                    let var20 := mulmod(a_0, a_2, R)
                    let var21 := addmod(var19, var20, R)
                    let a_1 := calldataload(0x0a44)
                    let a_3 := calldataload(0x0a84)
                    let var22 := mulmod(a_1, a_3, R)
                    let var23 := addmod(var21, var22, R)
                    let var24 := addmod(a_4_prev_1, var23, R)
                    let var25 := sub(R, var24)
                    let var26 := addmod(a_4, var25, R)
                    let var27 := mulmod(var18, var26, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var27, r)
                }
                {
                    let f_11 := calldataload(0x0c64)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x5
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let var16 := 0x7
                    let var17 := addmod(var16, var1, R)
                    let var18 := mulmod(var15, var17, R)
                    let a_4 := calldataload(0x0aa4)
                    let var19 := 0x0
                    let a_0 := calldataload(0x0a24)
                    let a_2 := calldataload(0x0a64)
                    let var20 := mulmod(a_0, a_2, R)
                    let var21 := addmod(var19, var20, R)
                    let a_1 := calldataload(0x0a44)
                    let a_3 := calldataload(0x0a84)
                    let var22 := mulmod(a_1, a_3, R)
                    let var23 := addmod(var21, var22, R)
                    let var24 := sub(R, var23)
                    let var25 := addmod(a_4, var24, R)
                    let var26 := mulmod(var18, var25, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var26, r)
                }
                {
                    let f_12 := calldataload(0x0c84)
                    let var0 := 0x1
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0aa4)
                    let a_2 := calldataload(0x0a64)
                    let var16 := mulmod(var0, a_2, R)
                    let a_3 := calldataload(0x0a84)
                    let var17 := mulmod(var16, a_3, R)
                    let var18 := sub(R, var17)
                    let var19 := addmod(a_4, var18, R)
                    let var20 := mulmod(var15, var19, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var20, r)
                }
                {
                    let f_12 := calldataload(0x0c84)
                    let var0 := 0x1
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x5
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x6
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0aa4)
                    let a_4_prev_1 := calldataload(0x0ae4)
                    let a_2 := calldataload(0x0a64)
                    let var16 := mulmod(var0, a_2, R)
                    let a_3 := calldataload(0x0a84)
                    let var17 := mulmod(var16, a_3, R)
                    let var18 := mulmod(a_4_prev_1, var17, R)
                    let var19 := sub(R, var18)
                    let var20 := addmod(a_4, var19, R)
                    let var21 := mulmod(var15, var20, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var21, r)
                }
                {
                    let f_13 := calldataload(0x0ca4)
                    let a_4 := calldataload(0x0aa4)
                    let var0 := 0x0
                    let a_2 := calldataload(0x0a64)
                    let var1 := addmod(var0, a_2, R)
                    let a_3 := calldataload(0x0a84)
                    let var2 := addmod(var1, a_3, R)
                    let var3 := sub(R, var2)
                    let var4 := addmod(a_4, var3, R)
                    let var5 := mulmod(f_13, var4, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var5, r)
                }
                {
                    let f_12 := calldataload(0x0c84)
                    let var0 := 0x1
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let var10 := 0x4
                    let var11 := addmod(var10, var1, R)
                    let var12 := mulmod(var9, var11, R)
                    let var13 := 0x5
                    let var14 := addmod(var13, var1, R)
                    let var15 := mulmod(var12, var14, R)
                    let a_4 := calldataload(0x0aa4)
                    let a_4_prev_1 := calldataload(0x0ae4)
                    let var16 := 0x0
                    let a_2 := calldataload(0x0a64)
                    let var17 := addmod(var16, a_2, R)
                    let a_3 := calldataload(0x0a84)
                    let var18 := addmod(var17, a_3, R)
                    let var19 := addmod(a_4_prev_1, var18, R)
                    let var20 := sub(R, var19)
                    let var21 := addmod(a_4, var20, R)
                    let var22 := mulmod(var15, var21, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var22, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(R, mulmod(l_0, calldataload(0x0de4), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x0e44)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, R), sub(R, perm_z_last), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0e44), sub(R, calldataload(0x0e24)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0e04)
                    let rhs := calldataload(0x0de4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0a24), mulmod(beta, calldataload(0x0ce4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0a44), mulmod(beta, calldataload(0x0d04), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0a64), mulmod(beta, calldataload(0x0d24), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0a84), mulmod(beta, calldataload(0x0d44), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0aa4), mulmod(beta, calldataload(0x0d64), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ac4), mulmod(beta, calldataload(0x0d84), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b04), mulmod(beta, calldataload(0x0da4), R), R), gamma, R), R)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0a24), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0a44), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0a64), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0a84), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0aa4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ac4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b04), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0e64)
                    let rhs := calldataload(0x0e44)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x0dc4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), R), gamma, R), R)
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0e84), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0e84), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0b24)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0be4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0a64)
                        let var1 := sub(R, a_2)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := 0x2
                        let var6 := addmod(var5, var1, R)
                        let var7 := mulmod(var0, var6, R)
                        let var8 := 0x3
                        let var9 := addmod(var8, var1, R)
                        let var10 := mulmod(var0, var9, R)
                        let var11 := 0x4
                        let var12 := addmod(var11, var1, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var10, var13, R)
                        let var15 := mulmod(var7, var14, R)
                        let var16 := mulmod(var4, var15, R)
                        let var17 := mulmod(f_7, var16, R)
                        let a_0 := calldataload(0x0a24)
                        let var18 := mulmod(var17, a_0, R)
                        let var19 := 0x18
                        let var20 := sub(R, var17)
                        let var21 := addmod(var19, var20, R)
                        let var22 := 0x0
                        let var23 := mulmod(var21, var22, R)
                        let var24 := addmod(var18, var23, R)
                        input_0 := var24
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x0ec4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x0ea4), sub(R, calldataload(0x0e84)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0ee4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0ee4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0b24)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x0c04)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0a84)
                        let var1 := sub(R, a_3)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := 0x2
                        let var6 := addmod(var5, var1, R)
                        let var7 := mulmod(var0, var6, R)
                        let var8 := 0x3
                        let var9 := addmod(var8, var1, R)
                        let var10 := mulmod(var0, var9, R)
                        let var11 := 0x4
                        let var12 := addmod(var11, var1, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var10, var13, R)
                        let var15 := mulmod(var7, var14, R)
                        let var16 := mulmod(var4, var15, R)
                        let var17 := mulmod(f_8, var16, R)
                        let a_1 := calldataload(0x0a44)
                        let var18 := mulmod(var17, a_1, R)
                        let var19 := 0x18
                        let var20 := sub(R, var17)
                        let var21 := addmod(var19, var20, R)
                        let var22 := 0x0
                        let var23 := mulmod(var21, var22, R)
                        let var24 := addmod(var18, var23, R)
                        input_0 := var24
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x0f24), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x0f04), sub(R, calldataload(0x0ee4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0f44), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0f44), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0b44)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0be4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0a64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := 0x2
                        let var4 := sub(R, a_2)
                        let var5 := addmod(var3, var4, R)
                        let var6 := mulmod(var0, var5, R)
                        let var7 := 0x3
                        let var8 := addmod(var7, var4, R)
                        let var9 := mulmod(var0, var8, R)
                        let var10 := 0x4
                        let var11 := addmod(var10, var4, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var9, var12, R)
                        let var14 := mulmod(var6, var13, R)
                        let var15 := mulmod(var2, var14, R)
                        let var16 := mulmod(f_7, var15, R)
                        let a_0 := calldataload(0x0a24)
                        let var17 := mulmod(var16, a_0, R)
                        let var18 := 0x6
                        let var19 := sub(R, var16)
                        let var20 := addmod(var18, var19, R)
                        let var21 := 0xff8
                        let var22 := mulmod(var20, var21, R)
                        let var23 := addmod(var17, var22, R)
                        input_0 := var23
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x0f84), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x0f64), sub(R, calldataload(0x0f44)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0fa4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0fa4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0b44)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x0c04)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0a84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := 0x2
                        let var4 := sub(R, a_3)
                        let var5 := addmod(var3, var4, R)
                        let var6 := mulmod(var0, var5, R)
                        let var7 := 0x3
                        let var8 := addmod(var7, var4, R)
                        let var9 := mulmod(var0, var8, R)
                        let var10 := 0x4
                        let var11 := addmod(var10, var4, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var9, var12, R)
                        let var14 := mulmod(var6, var13, R)
                        let var15 := mulmod(var2, var14, R)
                        let var16 := mulmod(f_8, var15, R)
                        let a_1 := calldataload(0x0a44)
                        let var17 := mulmod(var16, a_1, R)
                        let var18 := 0x6
                        let var19 := sub(R, var16)
                        let var20 := addmod(var18, var19, R)
                        let var21 := 0xff8
                        let var22 := mulmod(var20, var21, R)
                        let var23 := addmod(var17, var22, R)
                        input_0 := var23
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x0fe4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x0fc4), sub(R, calldataload(0x0fa4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1004), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1004), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0b64)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0be4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0a64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := sub(R, a_2)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x3
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var8, var11, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_7, var14, R)
                        let a_0 := calldataload(0x0a24)
                        let var16 := mulmod(var15, a_0, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffd
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x1ff0
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        input_0 := var22
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1044), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1024), sub(R, calldataload(0x1004)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1064), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1064), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0b64)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x0c04)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0a84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := sub(R, a_3)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x3
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var8, var11, R)
                        let var13 := mulmod(var0, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_8, var14, R)
                        let a_1 := calldataload(0x0a44)
                        let var16 := mulmod(var15, a_1, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffd
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x1ff0
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        input_0 := var22
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x10a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1084), sub(R, calldataload(0x1064)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x10c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x10c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0b84)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0be4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0a64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := sub(R, a_2)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_7, var14, R)
                        let a_0 := calldataload(0x0a24)
                        let var16 := mulmod(var15, a_0, R)
                        let var17 := 0x6
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x2fe8
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        input_0 := var22
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1104), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x10e4), sub(R, calldataload(0x10c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1124), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1124), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0b84)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x0c04)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0a84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := sub(R, a_3)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x4
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var0, var11, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_8, var14, R)
                        let a_1 := calldataload(0x0a44)
                        let var16 := mulmod(var15, a_1, R)
                        let var17 := 0x6
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x2fe8
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        input_0 := var22
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1164), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1144), sub(R, calldataload(0x1124)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1184), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1184), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x0ba4)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0be4)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0a64)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := sub(R, a_2)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x3
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var11, var0, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_7, var14, R)
                        let a_0 := calldataload(0x0a24)
                        let var16 := mulmod(var15, a_0, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffe9
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x3fe0
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        input_0 := var22
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x11c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x11a4), sub(R, calldataload(0x1184)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x11e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x11e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x0ba4)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x0c04)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0a84)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := sub(R, a_3)
                        let var3 := addmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(var1, var4, R)
                        let var6 := 0x2
                        let var7 := addmod(var6, var2, R)
                        let var8 := mulmod(var0, var7, R)
                        let var9 := 0x3
                        let var10 := addmod(var9, var2, R)
                        let var11 := mulmod(var0, var10, R)
                        let var12 := mulmod(var11, var0, R)
                        let var13 := mulmod(var8, var12, R)
                        let var14 := mulmod(var5, var13, R)
                        let var15 := mulmod(f_8, var14, R)
                        let a_1 := calldataload(0x0a44)
                        let var16 := mulmod(var15, a_1, R)
                        let var17 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffe9
                        let var18 := sub(R, var15)
                        let var19 := addmod(var17, var18, R)
                        let var20 := 0x3fe0
                        let var21 := mulmod(var19, var20, R)
                        let var22 := addmod(var16, var21, R)
                        input_0 := var22
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1224), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1204), sub(R, calldataload(0x11e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1244), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1244), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_6 := calldataload(0x0bc4)
                        table := f_6
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_9 := calldataload(0x0c24)
                        let var0 := 0x1
                        let var1 := mulmod(f_9, var0, R)
                        let a_0 := calldataload(0x0a24)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let input_1
                    {
                        let f_10 := calldataload(0x0c44)
                        let var0 := 0x1
                        let var1 := mulmod(f_10, var0, R)
                        let a_1 := calldataload(0x0a44)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_1 := var7
                        input_1 := addmod(input_1, beta, R)
                    }
                    let lhs
                    let rhs
                    {
                        let tmp := input_1
                        rhs := addmod(rhs, tmp, R)
                    }
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, tmp, R)
                        rhs := mulmod(rhs, table, R)
                    }
                    {
                        let tmp := input_0
                        tmp := mulmod(tmp, input_1, R)
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1284), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1264), sub(R, calldataload(0x1244)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, R)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, R)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x0400
                            let point_mptr := 0x0300
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(R, mload(point_mptr)), R))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03a0), R)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(R, point_1), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(R, point_2), R)
                    coeff := mulmod(coeff, addmod(point_0, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x0380), R)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_2, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_3, sub(R, point_2), R), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(R, point_3), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04a0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, R))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0cc4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), R), R)
                    for
                        {
                            let mptr := 0x0dc4
                            let mptr_end := 0x0cc4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    for
                        {
                            let mptr := 0x0ca4
                            let mptr_end := 0x0ae4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1284), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1224), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x11c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1164), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1104), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x10a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1044), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0fe4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0f84), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0f24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0ec4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0ac4), R), R)
                    for
                        {
                            let mptr := 0x0a84
                            let mptr_end := 0x0a04
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0ae4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0aa4), R), R)
                    r_eval := mulmod(r_eval, mload(0x0440), R)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0e24), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0de4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0e04), R), R)
                    r_eval := mulmod(r_eval, mload(0x0460), R)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1244), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1264), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x11e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1204), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1184), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x11a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1124), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1144), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x10c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x10e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1064), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1084), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1004), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1024), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0fa4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0fc4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0f44), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0f64), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0ee4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0f04), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0e84), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0ea4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0e44), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0e64), R), R)
                    r_eval := mulmod(r_eval, mload(0x0480), R)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), R)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), R)
                    sum := addmod(sum, mload(0xc0), R)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), R)
                    mstore(0x0580, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0520
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), R)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x04e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), R)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), R), R)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x07e4))
                    mstore(0x20, calldataload(0x0804))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x0d80
                            let mptr_end := 0x0800
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0464
                            let mptr_end := 0x0164
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0124
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x0164))
                    mstore(0xa0, calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x04a4))
                    mstore(0xa0, calldataload(0x04c4))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x07a4))
                    mstore(0xa0, calldataload(0x07c4))
                    for
                        {
                            let mptr := 0x0764
                            let mptr_end := 0x04a4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(R, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x12a4))
                    mstore(0xa0, calldataload(0x12c4))
                    success := ec_mul_tmp(success, sub(R, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x12e4))
                    mstore(0xa0, calldataload(0x1304))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x12e4))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x1304))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}