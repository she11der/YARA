rule SIGNATURE_BASE_OPCLEAVER_Jasus
{
	meta:
		description = "ARP cache poisoner used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "8e04b258-e071-5974-9778-b9d0b97be8d5"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L19-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7d6cd7f0f264a0bfdc6af422baa1a0e257cb8f4c39a2cb27a1edaf70201e8564"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "pcap_dump_open"
		$s2 = "Resolving IPs to poison..."
		$s3 = "WARNNING: Gateway IP can not be found"

	condition:
		all of them
}
