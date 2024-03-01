rule SIGNATURE_BASE_HKTL_FRP_INI_Apr20_1 : FILE
{
	meta:
		description = "Detects FRP fast reverse proxy tool INI file often used by threat groups"
		author = "Florian Roth (Nextron Systems)"
		id = "5c652c9c-715d-5ba5-821a-3e533b1e78c6"
		date = "2020-04-07"
		modified = "2023-12-05"
		reference = "Chinese Hacktools OpenDir"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_frp_proxy.yar#L24-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cc997dc876d7a49292b62a0fb4ff12b34dacacfd8a1b90226d6a9aee303cacdf"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "1dabef3c170e4e559c50d603d47fb7f66f6e3da75a65c3435b18175d6e9785bb"

	strings:
		$h1 = "[common]" ascii
		$s1 = "server_addr =" ascii fullword
		$s2 = "remote_port =" ascii fullword
		$s3 = "[RemoteDesktop]" ascii fullword
		$s4 = "local_ip = " ascii
		$s5 = "type = tcp" ascii fullword

	condition:
		uint16(0)==0x635b and filesize <1KB and $h1 at 0 and all of them
}
