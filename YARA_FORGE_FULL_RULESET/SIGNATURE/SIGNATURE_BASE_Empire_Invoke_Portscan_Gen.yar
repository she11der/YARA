rule SIGNATURE_BASE_Empire_Invoke_Portscan_Gen : FILE
{
	meta:
		description = "Detects Empire component - from files Invoke-Portscan.ps1, Invoke-Portscan.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "c2e01780-02d2-57d1-b38e-5c345ebccad6"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L502-L517"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "05e786dc42ee5ec56197803577d104595ad6554e028b7633b2f7fdf55a63e27c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash2 = "cf7030be01fab47e79e4afc9e0d4857479b06a5f68654717f3bc1bc67a0f38d3"

	strings:
		$s1 = "Test-Port -h $h -p $Port -timeout $Timeout" fullword ascii
		$s2 = "1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <100KB and 1 of them ) or all of them
}
