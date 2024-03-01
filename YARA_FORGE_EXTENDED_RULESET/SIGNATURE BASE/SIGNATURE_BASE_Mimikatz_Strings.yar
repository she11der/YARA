import "pe"

rule SIGNATURE_BASE_Mimikatz_Strings : FILE
{
	meta:
		description = "Detects Mimikatz strings"
		author = "Florian Roth (Nextron Systems)"
		id = "d8f63b71-c66c-5c10-9268-2d8970f7c8a1"
		date = "2016-06-08"
		modified = "2023-12-05"
		reference = "not set"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mimikatz.yar#L121-L154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "baba1e159c0fb23f68b80459291a2d2c52e84f742f51ca30b894f7fc6282ad7a"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "sekurlsa::logonpasswords" fullword wide ascii
		$x2 = "List tickets in MIT/Heimdall ccache" fullword ascii wide
		$x3 = "kuhl_m_kerberos_ptt_file ; LsaCallKerberosPackage %08x" fullword ascii wide
		$x4 = "* Injecting ticket :" fullword wide ascii
		$x5 = "mimidrv.sys" fullword wide ascii
		$x6 = "Lists LM & NTLM credentials" fullword wide ascii
		$x7 = "\\_ kerberos -" wide ascii
		$x8 = "* unknow   :" fullword wide ascii
		$x9 = "\\_ *Password replace ->" wide ascii
		$x10 = "KIWI_MSV1_0_PRIMARY_CREDENTIALS KO" ascii wide
		$x11 = "\\\\.\\mimidrv" wide ascii
		$x12 = "Switch to MINIDUMP :" fullword wide ascii
		$x13 = "[masterkey] with password: %s (%s user)" fullword wide
		$x14 = "Clear screen (doesn't work with redirections, like PsExec)" fullword wide
		$x15 = "** Session key is NULL! It means allowtgtsessionkey is not set to 1 **" fullword wide
		$x16 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " fullword wide

	condition:
		(( uint16(0)==0x5a4d and 1 of ($x*)) or (3 of them )) and not pe.imphash()=="77eaeca738dd89410a432c6bd6459907"
}
