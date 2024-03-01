rule SIGNATURE_BASE_Impacket_Lateral_Movement : FILE
{
	meta:
		description = "Detects Impacket Network Aktivity for Lateral Movement"
		author = "Markus Neis"
		id = "44db234c-ac81-5d21-bc2a-8cfd88807c0d"
		date = "2018-03-22"
		modified = "2023-12-05"
		reference = "https://github.com/CoreSecurity/impacket"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_impacket_tools.yar#L425-L443"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6628c27474d5235d5b510a55215762980a5b526b353b740344cb669e8e023e3c"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "impacket.dcerpc.v5.transport(" ascii
		$s2 = "impacket.smbconnection(" ascii
		$s3 = "impacket.dcerpc.v5.ndr(" ascii
		$s4 = "impacket.spnego(" ascii
		$s5 = "impacket.smb(" ascii
		$s6 = "impacket.ntlm(" ascii
		$s7 = "impacket.nmb(" ascii

	condition:
		uint16(0)==0x5a4d and filesize <14000KB and 2 of them
}
