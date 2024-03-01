rule GCTI_Cobaltstrike_Resources_Command_Ps1_V2_5_To_V3_7_And_Resources_Compress_Ps1_V3_8_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"
		author = "gssincla@google.com"
		id = "c0b81deb-ed20-5f7e-8e15-e6a9e9362594"
		date = "2022-11-18"
		modified = "2022-11-22"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x.yara#L17-L33"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"
		logic_hash = "31cf47060757b086d325cd205724a7be8931bbbc6ff2f4be67a6179ee99c42ca"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase
		$ps2 = "));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase

	condition:
		all of them
}
