rule SIGNATURE_BASE_Winpayloads_Payload___FILE
{
	meta:
		description = "Detects WinPayloads Payload"
		author = "Florian Roth (Nextron Systems)"
		id = "44fae324-1fc8-5417-950a-8a3783b6d2ae"
		date = "2017-07-11"
		modified = "2023-12-05"
		reference = "https://github.com/nccgroup/Winpayloads"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_winpayloads.yar#L30-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8a22eeafa320bcf0d41de402223d3ad51d8625ffaa68fe24be864ffcf72a64a2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "23a24f99c3c6c00cd4bf6cb968f813ba2ceadfa846c7f169f412bcbb71ba6573"
		hash2 = "35069905d9b7ba1fd57c8df03614f563504194e4684f47aafa08ebb8d9409d0b"
		hash3 = "a28d107f168d85c38fc76229b14561b472e60e60973eb10b6b554c1f57469322"
		hash4 = "ed93e28ca18f749a78678b1e8e8ac31f4c6c0bab2376d398b413dbdfd5af9c7f"
		hash5 = "26f5aee1ce65158e8375deb63c27edabfc9f5de3c1c88a4ce26a7e50b315b6d8"
		hash6 = "b25a515706085dbde0b98deaf647ef9a8700604652c60c6b706a2ff83fdcbf45"

	strings:
		$s1 = "bpayload.exe.manifest" fullword ascii
		$s2 = "spayload" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <10000KB and all of them )
}