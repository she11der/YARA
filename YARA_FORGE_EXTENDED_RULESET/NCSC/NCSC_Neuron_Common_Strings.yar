rule NCSC_Neuron_Common_Strings : FILE
{
	meta:
		description = "Rule for detection of Neuron based on commonly used strings"
		author = "NCSC UK"
		id = "b0f12276-300c-537e-b495-a06c97deccd7"
		date = "2018-02-06"
		modified = "2018-02-06"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/turla_neuron_nautilus.yar#L1-L23"
		license_url = "N/A"
		hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
		logic_hash = "ac5926d6173f291e7907a2ced61c9968660d24fdd28ed3dca097567040b059e3"
		score = 75
		quality = 55
		tags = "FILE"

	strings:
		$strServiceName = "MSExchangeService" ascii
		$strReqParameter_1 = "cadataKey" wide
		$strReqParameter_2 = "cid" wide
		$strReqParameter_3 = "cadata" wide
		$strReqParameter_4 = "cadataSig" wide
		$strEmbeddedKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnZ3WXRKcnNRZjVTcCtWVG9Rb2xuaEVkMHVwWDFrVElFTUNTNEFnRkRCclNmclpKS0owN3BYYjh2b2FxdUtseXF2RzBJcHV0YXhDMVRYazRoeFNrdEpzbHljU3RFaHBUc1l4OVBEcURabVVZVklVbHlwSFN1K3ljWUJWVFdubTZmN0JTNW1pYnM0UWhMZElRbnl1ajFMQyt6TUhwZ0xmdEc2b1d5b0hyd1ZNaz08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" wide
		$strDefaultKey = "8d963325-01b8-4671-8e82-d0904275ab06" wide
		$strIdentifier = "MSXEWS" wide
		$strListenEndpoint = "443/ews/exchange/" wide
		$strB64RegKeySubstring = "U09GVFdBUkVcTWljcm9zb2Z0XENyeXB0b2dyYXBo" wide
		$strName = "neuron_service" ascii
		$dotnetMagic = "BSJB" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $dotnetMagic and 6 of ($str*)
}
