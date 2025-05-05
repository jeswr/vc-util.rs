mkdir ./temp
cd ./temp
npx --yes @jeswr/vc-cli@1.15.0 generate --collect --distribute
cd ..
cp temp/generated/ed25519-preprocessed/barcode-bob-preprocessed.json ./ed25519-preprocessed.json
rm -rf ./temp
