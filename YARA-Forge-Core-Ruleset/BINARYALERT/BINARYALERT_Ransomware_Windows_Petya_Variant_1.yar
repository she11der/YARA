rule BINARYALERT_Ransomware_Windows_Petya_Variant_1
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
		author = "@fusionrace"
		id = "bf56c0e4-585c-509b-a182-a93c74be7524"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_petya_variant_1.yara#L1-L18"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "71b6a493388e7d0b40c83ce903bc6b04"
		logic_hash = "3733834ee2271a483739b09c4222d222aa4899cab48fd8fc558bdbd9a66bf2d6"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "Ooops, your important files are encrypted." fullword ascii wide
		$s2 = "Send your Bitcoin wallet ID and personal installation key to e-mail" fullword ascii wide
		$s3 = "wowsmith123456@posteo.net. Your personal installation key:" fullword ascii wide
		$s4 = "Send $300 worth of Bitcoin to following address:" fullword ascii wide
		$s5 = "have been encrypted.  Perhaps you are busy looking for a way to recover your" fullword ascii wide
		$s6 = "need to do is submit the payment and purchase the decryption key." fullword ascii wide

	condition:
		any of them
}