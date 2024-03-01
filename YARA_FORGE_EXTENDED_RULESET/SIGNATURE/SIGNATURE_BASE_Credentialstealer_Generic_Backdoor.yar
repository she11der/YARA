rule SIGNATURE_BASE_Credentialstealer_Generic_Backdoor : FILE
{
	meta:
		description = "Detects credential stealer byed on many strings that indicate password store access"
		author = "Florian Roth (Nextron Systems)"
		id = "b3124f6c-4e18-562c-84d9-d51e086da446"
		date = "2017-06-07"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_credstealer_generic.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "aa06291a91ac84f80cd2cbe5a01c2cbcc14cf6914da9d1234af9b3d833990551"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "edb2d039a57181acf95bd91b2a20bd9f1d66f3ece18506d4ad870ab65e568f2c"

	strings:
		$s1 = "GetOperaLoginData" fullword ascii
		$s2 = "GetInternetExplorerCredentialsPasswords" fullword ascii
		$s3 = "%s\\Opera Software\\Opera Stable\\Login Data" fullword ascii
		$s4 = "select *  from moz_logins" fullword ascii
		$s5 = "%s\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
		$s6 = "Host.dll.Windows" fullword ascii
		$s7 = "GetInternetExplorerVaultPasswords" fullword ascii
		$s8 = "GetWindowsLiveMessengerPasswords" fullword ascii
		$s9 = "%s\\Chromium\\User Data\\Default\\Login Data" fullword ascii
		$s10 = "%s\\Opera\\Opera\\profile\\wand.dat" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 4 of them )
}
