rule SIGNATURE_BASE_Empire_Agent_Gen : FILE
{
	meta:
		description = "Detects Empire component - from files agent.ps1, agent.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "0fac915c-2502-50da-93d1-f81e9282aa9a"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L430-L447"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ed8aee7ac6c1d93b21cc1aa5c3c18df1566692c63a010715a3aae65e18fffa60"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
		hash2 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"

	strings:
		$s1 = "$wc.Headers.Add(\"User-Agent\",$script:UserAgent)" fullword ascii
		$s2 = "$min = [int]((1-$script:AgentJitter)*$script:AgentDelay)" fullword ascii
		$s3 = "if ($script:AgentDelay -ne 0){" fullword ascii

	condition:
		( uint16(0)==0x660a and filesize <100KB and 1 of them ) or all of them
}
