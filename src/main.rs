fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod test {
    use bitcoin::{locktime::Height, LockTime, Sequence, hashes::hex::ToHex};
    use elements::{encode::deserialize, Block};

    #[test]
    fn verify_block_witness() {
        // set up secp256k1 verification context
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        // raw block bytes for block liquidv1 block with hash 325b1eee2bfdc449a00ddcc7fb464dd88446abdf6602e3688d718f20ca0ed5ae
        // which is at height 2_265_854
        let bytes = include_bytes!(
            "../blocks/325b1eee2bfdc449a00ddcc7fb464dd88446abdf6602e3688d718f20ca0ed5ae"
        );
        let block: Block = deserialize(bytes).unwrap();
        let header = block.header;

        // get the signblockscript of the current dynafed params
        let params = header.dynafed_current().unwrap();
        let signblockscript = params.signblockscript().unwrap();

        // and get the signblock witness
        let signblock_witness = if let elements::BlockExtData::Dynafed {
            ref signblock_witness,
            ..
        } = header.ext
        {
            signblock_witness
        } else {
            panic!("header is not dynafed");
        };
        let witness = bitcoin::Witness::from_vec(signblock_witness.clone());
        println!("witness data");
        for (i, w) in witness.iter().enumerate() {
            println!("witness index: {i}");
            let hex = w.to_hex();
            println!("hex: {hex}");
        }
        println!("---");

        // elements::Script and bitcoin::Script are separate newtypes, so convert this as required for miniscript
        let spk: bitcoin::Script = signblockscript.to_bytes().into();

        // set up a miniscript interpreter, to iterate through and verify each witness
        let script_sig = bitcoin::Script::new();
        let interpreter = miniscript::interpreter::Interpreter::from_txdata(
            &spk,
            &script_sig,
            &witness,
            Sequence(0),
            LockTime::Blocks(Height::from_consensus(0).unwrap())
        )
        .unwrap();

        // the block hash is the signed message
        let block_hash = header.block_hash();
        let message = bitcoin::secp256k1::Message::from_slice(&block_hash).unwrap();

        // create a closure for the miniscript interpreter custom iterator to use to verify each key/sig pair
        let sig_check = |sig: &miniscript::interpreter::KeySigPair| match sig {
            miniscript::interpreter::KeySigPair::Ecdsa(key, ecdsa_sig) => {
                println!("pubkey: {key}");
                println!("ecdsa_sig: {ecdsa_sig}");
                secp.verify_ecdsa(&message, &ecdsa_sig.sig, &key.inner)
                    .is_ok()
                    && ecdsa_sig.hash_ty == bitcoin::EcdsaSighashType::All
            }
            _ => panic!("schnorr sig instead of ecdsa"),
        };

        // create the custom iterator
        let verify_sig = Box::new(sig_check);
        let iterator = interpreter.iter_custom(verify_sig);

        // stepping through the iterator calls the sig check on each entry
        for (idx, result) in iterator.enumerate() {
            println!("iterator index: {idx}");
            match result {
                Ok(_) => {
                    println!("valid signblock witness at index {idx}");
                }
                Err(err) => {
                    panic!(
                        "Invalid signblock witness: signblockscript={:?}, witness={:?}, err={}",
                        signblockscript, witness, err
                    );
                }
            }
        }
    }
}
