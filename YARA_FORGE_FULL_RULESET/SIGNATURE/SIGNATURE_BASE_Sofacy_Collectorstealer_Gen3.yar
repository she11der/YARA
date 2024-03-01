rule SIGNATURE_BASE_Sofacy_Collectorstealer_Gen3 : FILE
{
	meta:
		description = "File collectors / USB stealers - Generic"
		author = "Florian Roth (Nextron Systems)"
		id = "d2ee1a22-6aae-51fc-9043-a7ba99769376"
		date = "2015-12-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sofacy_dec15.yar#L118-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		logic_hash = "8e7f56013629d8b4d0c7600552590e8073deb16d5b6dced11444c2110b88f387"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "NvCpld.dll" fullword ascii
		$s4 = "NvStart" fullword ascii
		$s5 = "NvStop" fullword ascii
		$a1 = "%.4d%.2d%.2d%.2d%.2d%.2d%.2d%.4d" fullword wide
		$a2 = "IGFSRVC.dll" fullword wide
		$a3 = "Common User Interface" fullword wide
		$a4 = "igfsrvc Module" fullword wide
		$b1 = " Operating System                        " fullword wide
		$b2 = "Microsoft Corporation                                       " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <150KB and ( all of ($s*) and ( all of ($a*) or all of ($b*)))
}
