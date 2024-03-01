import "pe"
import "math"

rule EMBEERESEARCH_Win_Pikabot_Resource_Entropy_Oct_2023
{
	meta:
		description = "Pikabot Loaders embedding encrypted inside of numerous png images"
		author = "Matthew @ Embee_Research"
		id = "253d35ae-a325-51c7-8da5-32bb46c51acd"
		date = "2023-10-03"
		modified = "2023-10-08"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_pikabot_resource_entropy_oct_2023.yar#L5-L40"
		license_url = "N/A"
		hash = "936247d9a0ce76bed17f03430186abb9ecafa88ef3a968cdd46c5b0a24a5cc3f"
		hash = "2c7b7c3ec8a6a835e07c8feed401460e185388f59ea5fc8aa8038d2b75815666"
		hash = "00239c55d7135aa06e21ace557a3e8bf3818c2e07051c84753209e7348b6a426"
		hash = "5f218eeb83c936d88b65ec3f3052d8c53f58775dacc04bedc91bd388fb7bb885"
		hash = "6bea3ecd1f43bdcc261719fb732fcf27e82ed6f4b086616925291a733f358a26"
		hash = "966042f3e532b6abce7d96bbdb91dc4561b32a4b0b9eec7b08b4f1024c2da916"
		hash = "951c906a1fa179050d30c06849d42e49a295dd1baad91efb244b2e5486b5801d"
		hash = "a06bd2623c389f2547d0bf750ca720ab7a74c90982267aad49ba31d5de345288"
		hash = "aeb2bf8898636b572b0703d9ddb90b9a4c5c6db9eee631ee726ad753f197ac12"
		logic_hash = "7beec034fc927990734691bd6859870921027860c0591c7a0d5a3815f919112d"
		score = 75
		quality = 50
		tags = ""

	strings:
		$s1 = "ARROW-DOWN" wide
		$s2 = "ARROW-LEFT" wide
		$s3 = "ARROW-RIGHT" wide

	condition:
		pe.DLL and ( all of ($s*)) and pe.number_of_resources>25 and pe.sections[3].raw_data_size>400KB and math.entropy(pe.sections[3].raw_data_offset,pe.sections[3].raw_data_size)>7.5
}
