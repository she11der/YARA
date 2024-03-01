import "pe"

rule ESET_Sparklinggoblin_Mutex
{
	meta:
		description = "SparklingGoblin ChaCha20 loaders mutexes"
		author = "ESET Research"
		id = "e33d2bc1-29d6-5117-8e0f-31f8bced0979"
		date = "2021-05-20"
		modified = "2021-08-26"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/sparklinggoblin/SparklingGoblin.yar#L465-L489"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		hash = "2edbea43f5c40c867e5b6bbd93cc972525df598b"
		hash = "b6d245d3d49b06645c0578804064ce0c072cbe0f"
		hash = "8be6d5f040d0085c62b1459afc627707b0de89cf"
		hash = "4668302969fe122874fb2447a80378dcb671c86b"
		hash = "9bdecb08e16a23d271d0a3e836d9e7f83d7e2c3b"
		hash = "9ce7650f2c08c391a35d69956e171932d116b8bd"
		logic_hash = "00fbd514c8e2d6dea3b0f175e857a613e158b64caf1f970e814d62f1ebe9d35c"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"

	strings:
		$mutex_1 = "kREwdFrOlvASgP4zWZyV89m6T2K0bIno"
		$mutex_2 = "v5EPQFOImpTLaGZes3Nl1JSKHku8AyCw"

	condition:
		any of them
}
