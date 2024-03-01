rule SIGNATURE_BASE_Shellcrew_Streamex_1_Msi_Dll : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "56586e0b-010a-5ad5-8822-5d370475aa06"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_shellcrew_streamex.yar#L82-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "087ac07a2bf822f7838ef46296150381cfc9af9b12b4023654023a779efc1db1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "883108119d2f4db066fa82e37aa49ecd2dbdacda67eb936b96720663ed6565ce"
		hash2 = "5311f862d7c824d13eea8293422211e94fb406d95af0ae51358accd4835aaef8"
		hash3 = "191cbeffa36657ab1ef3939da023cacbc9de0285bbe7775069c3d6e18b372c3f"

	strings:
		$s1 = "NDOGDUA" fullword ascii
		$s2 = "NsrdsrN" fullword ascii

	condition:
		( uint16(0)==0x4d9d and filesize <300KB and all of them )
}
