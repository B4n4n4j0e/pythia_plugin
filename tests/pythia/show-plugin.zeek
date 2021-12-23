# @TEST-EXEC: zeek -NN Prod::Pythia |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
