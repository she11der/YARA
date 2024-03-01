import "pe"

rule ARKBIRD_SOLG_APT_MAL_NK_Lazarus_Dacls_June_2020_1 : FILE
{
	meta:
		description = "Detect DACLS malware used by APT Lazarus"
		author = "Arkbird_SOLG"
		id = "fb85b83a-4367-5f1d-be06-8a8e906b8df7"
		date = "2020-06-11"
		modified = "2020-06-12"
		reference = "https://twitter.com/batrix20/status/1270924079826997248"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-12/Lazarus/Lazarus_June_2020_1.yar#L3-L26"
		license_url = "N/A"
		logic_hash = "ed3e4a7a0490c5e8854d4e1bc8a223658ab9657a03c1b237af1056293a51611b"
		score = 75
		quality = 48
		tags = "FILE"
		hash1 = "2dd57d67e486d6855df8235c15c9657f39e488ff5275d0ce0fcec7fc8566c64b"

	strings:
		$s1 = "bash -i > /dev/tcp/" fullword ascii
		$s2 = "__mh_execute_header" fullword ascii
		$s3 = "/bin/bash -c \"" fullword ascii
		$s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36" fullword ascii
		$s5 = "@_gethostbyname" fullword ascii
		$s6 = "@_gethostname" fullword ascii
		$s7 = "radr://5614542" fullword ascii
		$s8 = "sh -c \"" fullword ascii
		$s9 = "content-type: multipart/form-data" fullword ascii
		$s10 = "@___stack_chk_fail" fullword ascii
		$s11 = "/usr/lib/libSystem.B.dylib" fullword ascii
		$s12 = "@dyld_stub_binder" fullword ascii

	condition:
		uint16(0)==0xfacf and filesize <200KB and 10 of them
}
