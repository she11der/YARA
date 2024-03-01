rule MALPEDIA_Win_Unidentified_102_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "68f5ede2-e772-5b9c-86c7-72da7d6ddaff"
		date = "2023-07-11"
		modified = "2023-07-15"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_102"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_102_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "7cf959abf8b06a75a101a66334f27ae5601df812c1ddb140fd9298ef735bb0dc"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 6bd238 8b0c8d187b0410 88441129 8b0b 8bc1 c1f806 }
		$sequence_1 = { 83c408 8bb5e8fdffff 8dbdd8fdffff 83bdecfdffff10 c745b000000000 0f43bdd8fdffff }
		$sequence_2 = { 8bf3 6bf938 c1fe06 6a00 8b0cb5187b0410 ff740f24 }
		$sequence_3 = { 894610 c7461407000000 668906 e9???????? 837f1410 8bcf 7202 }
		$sequence_4 = { c785e4fbffff07000000 8d5102 668985d0fbffff 6690 668b01 83c102 6685c0 }
		$sequence_5 = { 8d85e8e7ffff 68???????? 50 ff15???????? 83c410 8d8594e7ffff 50 }
		$sequence_6 = { 0f1085b0fcffff 0f1100 8bc4 0f108590fcffff 51 0f1100 ff5228 }
		$sequence_7 = { 83c408 8b95dcfeffff 83fa10 722f 8b8dc8feffff 42 8bc1 }
		$sequence_8 = { 6a00 68???????? 6802000080 c785c8e7ffff3f000f00 ff15???????? 85c0 0f84ef000000 }
		$sequence_9 = { 8d45f4 64a300000000 8965f0 8b4510 8b4d18 8b5d0c }

	condition:
		7 of them and filesize <626688
}
