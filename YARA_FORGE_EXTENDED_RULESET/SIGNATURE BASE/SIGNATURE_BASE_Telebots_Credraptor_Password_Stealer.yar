rule SIGNATURE_BASE_Telebots_Credraptor_Password_Stealer : FILE
{
	meta:
		description = "Detects TeleBots malware - CredRaptor Password Stealer"
		author = "Florian Roth (Nextron Systems)"
		id = "f594a946-13b4-5179-9029-a0730634d55f"
		date = "2016-12-14"
		modified = "2023-01-06"
		reference = "https://goo.gl/4if3HG"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_telebots.yar#L70-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ed884cb7643a61109f87e2887bed7ddb838c73bce28812b76c35bb807629e116"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "50b990f6555055a265fde98324759dbc74619d6a7c49b9fd786775299bf77d26"

	strings:
		$s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\GetPAI\\Out\\IE.pdb" fullword ascii
		$s2 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" fullword ascii
		$s3 = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS" fullword ascii
		$s4 = ".\\PAI\\IEforXPpasswords.txt" ascii
		$s5 = "\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
		$s6 = "Opera old version credentials" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them ) or (4 of them )
}
