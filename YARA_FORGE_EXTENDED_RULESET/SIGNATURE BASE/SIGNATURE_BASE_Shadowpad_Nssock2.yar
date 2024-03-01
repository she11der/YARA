import "pe"

rule SIGNATURE_BASE_Shadowpad_Nssock2 : FILE
{
	meta:
		description = "Detects malicious nssock2.dll from ShadowPad incident - file nssock2.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "47ecc7f8-065a-558b-9bba-300fd28f4eab"
		date = "2017-08-15"
		modified = "2023-12-05"
		reference = "https://securelist.com/shadowpad-in-corporate-networks/81432/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_shadowpad.yar#L13-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ea9675d5acfdc80cfa787db2c2dfe2169aa7c5e3ead35f020d0b0b664ecb4bf4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"
		hash2 = "c45116a22cf5695b618fcdf1002619e8544ba015d06b2e1dbf47982600c7545f"
		hash3 = "696be784c67896b9239a8af0a167add72b1becd3ef98d03e99207a3d5734f6eb"
		hash4 = "515d3110498d7b4fdb451ed60bb11cd6835fcff4780cb2b982ffd2740e1347a0"
		hash5 = "536d7e3bd1c9e1c2fd8438ab75d6c29c921974560b47c71686714d12fb8e9882"
		hash6 = "637fa40cf7dd0252c87140f7895768f42a370551c87c37a3a77aac00eb17d72e"

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="c67de089f2009b21715744762fc484e8" or pe.imphash()=="11522f7d4b2fc05acba8f534ca1b828a"))
}
