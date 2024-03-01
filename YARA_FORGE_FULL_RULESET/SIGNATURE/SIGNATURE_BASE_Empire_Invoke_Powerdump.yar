rule SIGNATURE_BASE_Empire_Invoke_Powerdump : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-PowerDump.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "d1082a4e-d458-57fb-b332-7c775c8ef2dd"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L59-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e460d015be54a88d0eb5741a9c32cf6d7a410e0beb5356402af0dd19d1b4c6f2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "095c5cf5c0c8a9f9b1083302e2ba1d4e112a410e186670f9b089081113f5e0e1"

	strings:
		$x16 = "$enc = Get-PostHashdumpScript" fullword ascii
		$x19 = "$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;" fullword ascii
		$x20 = "$rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);" fullword ascii

	condition:
		( uint16(0)==0x2023 and filesize <60KB and 1 of them ) or all of them
}
