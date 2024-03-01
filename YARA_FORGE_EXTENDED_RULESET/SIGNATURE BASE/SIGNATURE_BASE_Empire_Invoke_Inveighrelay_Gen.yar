rule SIGNATURE_BASE_Empire_Invoke_Inveighrelay_Gen : FILE
{
	meta:
		description = "Detects Empire component - from files Invoke-InveighRelay.ps1, Invoke-InveighRelay.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "0adebf6f-99e1-5461-8efc-e4660faf6d5d"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L469-L484"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "183a0afa9233e380471ddfa8f85e6c6555d69c785c9a4e8791e19432b6849558"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash2 = "21b90762150f804485219ad36fa509aeda210d46453307a9761c816040312f41"

	strings:
		$s1 = "$inveigh.SMBRelay_failed_list.Add(\"$HTTP_NTLM_domain_string\\$HTTP_NTLM_user_string $SMBRelayTarget\")" fullword ascii
		$s2 = "$NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <200KB and 1 of them ) or all of them
}
