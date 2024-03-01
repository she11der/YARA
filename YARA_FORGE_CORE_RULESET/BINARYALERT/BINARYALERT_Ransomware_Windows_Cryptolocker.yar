rule BINARYALERT_Ransomware_Windows_Cryptolocker
{
	meta:
		description = "The CryptoLocker malware propagated via infected email attachments, and via an existing botnet; when activated, the malware encrypts files stored on local and mounted network drives"
		author = "@fusionrace"
		id = "be205f4b-d078-5437-bacc-203c816db2fa"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://www.secureworks.com/research/cryptolocker-ransomware"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_cryptolocker.yara#L1-L21"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "012d9088558072bc3103ab5da39ddd54"
		logic_hash = "317cbc01b4c329befeb5b25478f7827298a26d21b872ae232c519febd9c547fc"
		score = 75
		quality = 80
		tags = ""

	strings:
		$u0 = "Paysafecard is an electronic payment method for predominantly online shopping" fullword ascii wide
		$u1 = "bb to select the method of payment and the currency." fullword ascii wide
		$u2 = "Where can I purchase a MoneyPak?" fullword ascii wide
		$u3 = "Ukash is electronic cash and e-commerce brand." fullword ascii wide
		$u4 = "You have to send below specified amount to Bitcoin address" fullword ascii wide
		$u5 = "cashU is a prepaid online" fullword ascii wide
		$u6 = "Your important files \\b encryption" fullword ascii wide
		$u7 = "Encryption was produced using a \\b unique\\b0  public key" fullword ascii wide
		$u8 = "then be used to pay online, or loaded on to a prepaid card or eWallet." fullword ascii wide
		$u9 = "Arabic online gamers and e-commerce buyers." fullword ascii wide

	condition:
		2 of them
}
