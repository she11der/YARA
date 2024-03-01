rule SIGNATURE_BASE_CN_Honker_T00Ls_Lpk_Sethc_V4_0 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v4.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d41cbed5-a6e3-5165-a8c3-e0375c1ed75d"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L377-L392"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "98f21f72c761e504814f0a7db835a24a2413a6c2"
		logic_hash = "bd6f9b6e831573164fddf7f0188087eb0076410b77c9c06cfacadebe6a53b525"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "LOADER ERROR" fullword ascii
		$s15 = "2011-2012 T00LS&RICES" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2077KB and all of them
}
