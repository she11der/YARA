rule SIGNATURE_BASE_SUSP_Netsh_Portproxy_Command
{
	meta:
		description = "Detects a suspicious command line with netsh and the portproxy command"
		author = "Florian Roth (Nextron Systems)"
		id = "cbbd2042-572c-5283-bd45-e745b36733ad"
		date = "2019-04-20"
		modified = "2023-12-05"
		reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L287-L300"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dbf82a908e77886af1c31c51f5f6684015cbcb22bf28876c2e1b0dd1ea5bd2b4"
		score = 65
		quality = 85
		tags = ""
		hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"

	strings:
		$x1 = "netsh interface portproxy add v4tov4 listenport=" ascii

	condition:
		1 of them
}
