rule MALPEDIA_Win_Smokeloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "977bd971-8931-5636-8c4a-15a97d7d7052"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smokeloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.smokeloader_auto.yar#L1-L568"
		license_url = "N/A"
		logic_hash = "1e0a8327807cdebec07ee883bf0e214c6531b2f2bf2969115a759b540a5a3955"
		score = 75
		quality = 50
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { ff15???????? 8d45f0 50 8d45e8 50 8d45e0 50 }
		$sequence_1 = { 57 ff15???????? 6a00 6800000002 6a03 6a00 6a03 }
		$sequence_2 = { 50 8d45e0 50 56 ff15???????? 56 ff15???????? }
		$sequence_3 = { 8bf0 8d45dc 50 6a00 53 ff15???????? }
		$sequence_4 = { 740a 83c104 83f920 72f0 }
		$sequence_5 = { e8???????? 8bf0 8d45fc 50 ff75fc 56 6a19 }
		$sequence_6 = { ff15???????? bf90010000 8bcf e8???????? }
		$sequence_7 = { 0fb64405dc 50 8d45ec 50 }
		$sequence_8 = { 50 56 681f000f00 57 }
		$sequence_9 = { 56 8d45fc 50 57 57 6a19 }
		$sequence_10 = { 668ce8 6685c0 7406 fe05???????? }
		$sequence_11 = { 8b07 03c3 50 ff15???????? }
		$sequence_12 = { 56 ff15???????? 50 56 6a00 ff15???????? }
		$sequence_13 = { 33c0 e9???????? e8???????? b904010000 }
		$sequence_14 = { 88443c18 88543418 0fb64c3c18 0fb6c2 03c8 81e1ff000000 }
		$sequence_15 = { 81e5ff000000 8a442c18 88443c18 47 }
		$sequence_16 = { e8???????? 8bf8 68???????? ff15???????? }
		$sequence_17 = { ebf5 55 8bec 83ec24 8d45f4 53 }
		$sequence_18 = { 50 57 ff15???????? 43 83fb0f }
		$sequence_19 = { 8b7d10 50 57 56 53 e8???????? }
		$sequence_20 = { 8d8de8fdffff 50 50 50 }
		$sequence_21 = { 8d95f0fdffff c70200000000 6800800000 52 51 6aff }
		$sequence_22 = { 8985ecfdffff ffb5f0fdffff 50 53 e8???????? 8d8decfdffff }
		$sequence_23 = { e8???????? 2500300038 005800 2500300038 }
		$sequence_24 = { 8db5f8fdffff c60653 56 6a00 6a00 6a00 }
		$sequence_25 = { 8b4514 898608020000 56 6aff }
		$sequence_26 = { 01d4 8d85f0fdffff 8b750c 8b7d10 50 57 }
		$sequence_27 = { fc 5f 5e 5b }
		$sequence_28 = { 89e5 81ec5c060000 53 56 }
		$sequence_29 = { 30d0 aa e2f3 7505 }
		$sequence_30 = { 89cf fc b280 31db a4 }
		$sequence_31 = { 60 89c6 89cf fc }
		$sequence_32 = { ff15???????? 85c0 747c 488b4c2448 4533c9 488d442440 }
		$sequence_33 = { 488b4547 488907 4885c9 740f 8b450f 48894d17 83c802 }
		$sequence_34 = { 33c9 e8???????? 488bd8 4584ff 7411 41b101 }
		$sequence_35 = { 4f 8d1c10 41 8b4b18 45 }
		$sequence_36 = { 01c4 ffc9 49 8d3c8c }
		$sequence_37 = { 4c 01c7 8b048f 4c }
		$sequence_38 = { 49 8d3c8c 8b37 4c 01c6 }
		$sequence_39 = { 41b104 448bc7 488bcb e8???????? 488b742440 488bc3 488b5c2430 }
		$sequence_40 = { 55 89e5 81ec54040000 53 }
		$sequence_41 = { 33c9 4c897c2428 c744242000a00f00 ff15???????? }
		$sequence_42 = { 8b4b18 45 8b6320 4d }
		$sequence_43 = { 89d0 c1e205 01c2 31c0 ac 01c2 85c0 }
		$sequence_44 = { 83c408 85c0 0f84cb000000 8b45f4 2d10bf3400 0fb74dec }
		$sequence_45 = { 8946fc ad 85c0 75f3 c3 56 }
		$sequence_46 = { 56 ad 01e8 31c9 c1c108 3208 }
		$sequence_47 = { 8b4da0 8b55a4 895148 689d1e6b63 8b45e4 50 }
		$sequence_48 = { 8b45b4 894220 eb10 8b8d78ffffff 8b11 899578ffffff ebae }
		$sequence_49 = { 03471c 8b0428 01e8 5e c3 }
		$sequence_50 = { 5b c9 c20800 55 89e5 83ec04 }
		$sequence_51 = { e8???????? 8945ac 6a00 6a04 8d45b4 50 }
		$sequence_52 = { aa e2f3 7506 7404 }
		$sequence_53 = { 55 8bec 83c4d0 1e 53 }
		$sequence_54 = { 684a0dce09 8b45e4 50 e8???????? 8945a8 8b4da0 8b55a8 }
		$sequence_55 = { 83ec0c e8???????? 8945f8 8b45f8 8b4860 894df4 ff7518 }
		$sequence_56 = { 803800 75f5 31d1 75ec }
		$sequence_57 = { 8b450c 2d10bf3400 8b4d08 c1e103 }
		$sequence_58 = { 8b55f8 0fb70a c1e103 33d2 f7f1 8945fc }
		$sequence_59 = { 5e c3 60 89c6 }
		$sequence_60 = { 9a18a15c5d5d5d d6 0055d0 08a50f375d37 }
		$sequence_61 = { 48 35f94e5d5d d6 59 79de 99 }
		$sequence_62 = { 5d 5d b658 1f 79b6 a888 }
		$sequence_63 = { 0055d0 08a50f375d37 5d 37 }
		$sequence_64 = { 5d 5d 285829 5e cb }

	condition:
		7 of them and filesize <245760
}
