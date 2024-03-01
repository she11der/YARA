rule SIGNATURE_BASE_Powershell_JAB_B64 : FILE
{
	meta:
		description = "Detects base464 encoded $ sign at the beginning of a string"
		author = "Florian Roth (Nextron Systems)"
		id = "c18fa17b-aaa5-5a89-bc25-3cc51b5af103"
		date = "2018-04-02"
		modified = "2023-12-05"
		reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_susp.yar#L207-L221"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4746a73774f945e63455ca7dd58ef67290f7c66d2dca80d06d52d2545c69a190"
		score = 60
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "('JAB" ascii wide
		$s2 = "powershell" nocase

	condition:
		filesize <30KB and all of them
}
