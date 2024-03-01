import "pe"

rule SIGNATURE_BASE_Pstgdump : FILE
{
	meta:
		description = "Detects a tool used by APT groups - file pstgdump.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "86a105a3-b5b5-58b2-99bd-ec05f31adb6b"
		date = "2016-09-08"
		modified = "2023-12-05"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3281-L3299"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0c4f8697b1b65007acc4fdabd1c6263a428448232f95dbb12d8f737297893157"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "65d48a2f868ff5757c10ed796e03621961954c523c71eac1c5e044862893a106"

	strings:
		$x1 = "\\Release\\pstgdump.pdb" ascii
		$x2 = "Failed to dump all protected storage items - see previous messages for details" fullword ascii
		$x3 = "ptsgdump [-h][-q][-u Username][-p Password]" fullword ascii
		$x4 = "Attempting to impersonate domain user '%s' in domain '%s'" fullword ascii
		$x5 = "Failed to impersonate user (ImpersonateLoggedOnUser failed): error %d" fullword ascii
		$x6 = "Unable to obtain handle to PStoreCreateInstance in pstorec.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of ($x*)) or (3 of them )
}
