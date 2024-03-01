rule SIGNATURE_BASE_Ps1_Toolkit_Inveigh_Bruteforce : FILE
{
	meta:
		description = "Auto-generated rule - file Inveigh-BruteForce.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "cdc298d3-f9ac-5472-bdc9-0dc51ad91e4a"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_toolkit.yar#L33-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b23b6ad66e054e435415464262004ead6e7ee121185d76c02110506293b3867b"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"

	strings:
		$s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
		$s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
		$s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii

	condition:
		( uint16(0)==0xbbef and filesize <300KB and 1 of them ) or (2 of them )
}
