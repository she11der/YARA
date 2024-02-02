rule ESET_Sparklinggoblin_Chacha20Loader_Richheader
{
	meta:
		description = "Rule matching ChaCha20 loaders rich header"
		author = "ESET Research"
		id = "e1dac369-f25e-5cb3-aafa-b0c45f05b295"
		date = "2021-03-30"
		modified = "2021-08-26"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/sparklinggoblin/SparklingGoblin.yar#L33-L57"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		hash = "09ffe37a54bc4ebebd8d56098e4c76232f35d821"
		hash = "29b147b76bb0d9e09f7297487cb972e6a2905586"
		hash = "33f2c3de2457b758fc5824a2b253ad7c7c2e9e37"
		hash = "45bef297ce78521eac6ee39e7603e18360e67c5a"
		hash = "4cec7cdc78d95c70555a153963064f216dae8799"
		hash = "4d4c1a062a0390b20732ba4d65317827f2339b80"
		hash = "4f6949a4906b834e83ff951e135e0850fe49d5e4"
		logic_hash = "a5c9595036dec0e0aef0a030c590189752217d15d3f53bf3dc537f5b43fae63e"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"

	condition:
		pe.rich_signature.length>=104 and pe.rich_signature.length<=112 and pe.rich_signature.toolid(241,40116)>=5 and pe.rich_signature.toolid(241,40116)<=10 and pe.rich_signature.toolid(147,30729)==11 and pe.rich_signature.toolid(264,24215)>=15 and pe.rich_signature.toolid(264,24215)<=16
}