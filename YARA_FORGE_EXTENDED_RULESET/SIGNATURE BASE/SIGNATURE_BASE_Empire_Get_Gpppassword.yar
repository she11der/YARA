rule SIGNATURE_BASE_Empire_Get_Gpppassword : FILE
{
	meta:
		description = "Detects Empire component - file Get-GPPPassword.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "7791b009-19d3-5d08-8ef7-4723d28830ed"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L140-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3c879e50805e8b89fc8f3a7c7da2c8e906c89f210ab74194daca6b0ba2d312ba"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "55a4519c4f243148a971e4860225532a7ce730b3045bde3928303983ebcc38b0"

	strings:
		$s1 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
		$s2 = "$XMlFiles += Get-ChildItem -Path \"\\\\$DomainController\\SYSVOL\" -Recurse" ascii
		$s3 = "function Get-DecryptedCpassword {" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <30KB and 1 of them ) or all of them
}
