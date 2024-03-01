rule SIGNATURE_BASE_Empire_Invoke_Smbscanner : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-SmbScanner.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "63cd048b-04fd-5b4f-9d4d-3a001c31b4df"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L157-L171"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5feb32dd0fc5271256dc4a088b9b02b591dbe584759db7ee4f5a6c99f42c3c0c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"

	strings:
		$s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
		$s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <10KB and 1 of them ) or all of them
}
