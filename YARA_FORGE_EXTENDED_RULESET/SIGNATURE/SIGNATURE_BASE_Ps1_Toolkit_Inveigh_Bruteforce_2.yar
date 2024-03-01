rule SIGNATURE_BASE_Ps1_Toolkit_Inveigh_Bruteforce_2 : FILE
{
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "1319b03d-67e8-5155-8037-e3375e39f6a0"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_toolkit.yar#L164-L181"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5c035898a9574e2516cbc66efcf57f7380fd979c4a5099f8a0a190ad21af32c0"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"

	strings:
		$s1 = "}.NTLMv2_file_queue[0]|Out-File ${" ascii
		$s2 = "}.NTLMv2_file_queue.RemoveRange(0,1)" ascii
		$s3 = "}.NTLMv2_file_queue.Count -gt 0)" ascii
		$s4 = "}.relay_running = $false" ascii

	condition:
		( uint16(0)==0xbbef and filesize <200KB and 2 of them ) or (4 of them )
}
