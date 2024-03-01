rule BINARYALERT_Hacktool_Macos_N0Fate_Chainbreaker
{
	meta:
		description = "chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner."
		author = "@mimeframe"
		id = "565d31c6-8d80-534d-8acc-c01d7af4f8b3"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/n0fate/chainbreaker"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_n0fate_chainbreaker.yara#L1-L13"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "7aedf952756ed2375ff171329179f14a8cdc37ada69e1f003def1f1de5bc1691"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "[!] Private Key Table is not available" wide ascii
		$a2 = "[!] Public Key Table is not available" wide ascii
		$a3 = "[-] Decrypted Private Key" wide ascii

	condition:
		all of ($a*)
}
