rule MALPEDIA_Win_Dreambot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6c3809b8-d477-5125-8734-0179b265a99d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dreambot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dreambot_auto.yar#L1-L1031"
		license_url = "N/A"
		logic_hash = "d649e332b74326d8b7e280b52a73b7636b1baab8e64673c71262bd2586c99629"
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
		$sequence_0 = { a802 7410 8b4730 a840 7509 83672800 e9???????? }
		$sequence_1 = { 897b20 8b4320 c6400731 8b742414 8b3e 6a00 }
		$sequence_2 = { 7454 68???????? 68???????? ff7320 e8???????? }
		$sequence_3 = { 0f8555ffffff 894730 e9???????? 55 8bec }
		$sequence_4 = { 85f6 0f84a9000000 e8???????? 85c0 0f8483000000 }
		$sequence_5 = { e8???????? 8bf8 85ff 755a 39451c 7475 }
		$sequence_6 = { 751a 395d10 7413 8b4618 e8???????? eb09 ff7618 }
		$sequence_7 = { 51 51 33c0 50 56 ff5214 8bfb }
		$sequence_8 = { 53 68???????? eb54 3bf3 745c 395d0c 7457 }
		$sequence_9 = { 837d0c04 7516 ff7510 ff36 68???????? }
		$sequence_10 = { ebcc 3bf3 7474 395d0c 746f 6a0d }
		$sequence_11 = { 3bf3 0f8496000000 395d0c 0f848d000000 6a07 ebdd }
		$sequence_12 = { 3bf3 0f8481000000 395d0c 747c 6a03 }
		$sequence_13 = { e8???????? 894508 8b7d08 eb24 a1???????? 85c0 7520 }
		$sequence_14 = { 745c 395d0c 7457 53 ff750c 8bfe c7450857000000 }
		$sequence_15 = { e8???????? e9???????? 3bf3 0f8496000000 }
		$sequence_16 = { 4803542460 41ff5220 4c8b442460 e9???????? }
		$sequence_17 = { e8???????? 4c8b1d???????? ba0d000000 41834b3401 }
		$sequence_18 = { 0f84b5000000 413bf5 0f84ac000000 41b807000000 ebd7 493bfd }
		$sequence_19 = { 4c896c2420 e8???????? 4c8b442468 488b0d???????? 33d2 }
		$sequence_20 = { 7423 41b904000000 413bf1 7518 8b17 }
		$sequence_21 = { 418d5620 498bcf ff15???????? 4c8bf0 4885c0 }
		$sequence_22 = { 498bcb 492bd0 4803542460 41ff5220 }
		$sequence_23 = { 0f8492000000 41b803000000 ebbd 493bfd 0f8481000000 413bf5 }
		$sequence_24 = { 4c8b18 488b542460 4533c9 488bc8 41ff5318 }
		$sequence_25 = { 488d5e10 4533f6 488b0b 2580000000 418d5620 }
		$sequence_26 = { ff15???????? e9???????? 493bfd 0f84d9000000 }
		$sequence_27 = { e8???????? eb2c 8b05???????? 413bc5 7528 }
		$sequence_28 = { 488b9424a8000000 4533c9 4533c0 ff5028 }
		$sequence_29 = { 0f8481000000 413bf5 747c 41b80d000000 }
		$sequence_30 = { 488bcf e8???????? e9???????? 493bfd 0f84b5000000 }
		$sequence_31 = { 5f c3 4053 4883ec20 4c8b4108 488bd9 4d85c0 }
		$sequence_32 = { 0f849b000000 413bf5 0f8492000000 41b803000000 ebbd }
		$sequence_33 = { 33d2 89442448 ff15???????? 33d2 }
		$sequence_34 = { 33d2 3bc2 0f85bd000000 33c0 89942498000000 }
		$sequence_35 = { e8???????? 488b5c2428 85c0 753e 8b9424c8000000 }
		$sequence_36 = { 3decc7eea6 0f84e8000000 3d0470a8c4 0f8486000000 }
		$sequence_37 = { 488b0d???????? 4d8bc4 33d2 ff15???????? 488bf8 }
		$sequence_38 = { 4883ec30 837a3c04 4c8b2a 488bf2 488bd9 }
		$sequence_39 = { 89750c 8d750c e8???????? 8bf0 }
		$sequence_40 = { 4883c208 4883e901 75e2 837c243801 0f86b2000000 }
		$sequence_41 = { 8b450c 33db 895dfc e8???????? 8945f8 33ff eb03 }
		$sequence_42 = { 75f5 eb06 8b05???????? 35fc5585cf 4533c9 }
		$sequence_43 = { ff7310 ff15???????? 33d2 89b7184a0000 39971c4a0000 }
		$sequence_44 = { ff33 50 6810040000 ff15???????? 8945fc }
		$sequence_45 = { 56 33f6 46 8945f8 }
		$sequence_46 = { c3 6a00 6800004000 6a00 ff15???????? a3???????? 85c0 }
		$sequence_47 = { 46 8945f8 85c0 7551 }
		$sequence_48 = { 57 4883ec20 8b05???????? 8364243800 }
		$sequence_49 = { ff15???????? 8945fc 85c0 741a 6804010000 }
		$sequence_50 = { 85c0 7551 ff33 50 }
		$sequence_51 = { eb03 8b750c ff75f8 69f60d661900 ff75f4 81c65ff36e3c 89750c }
		$sequence_52 = { 817424105085b8ed 33ff 47 57 be???????? 56 8d542418 }
		$sequence_53 = { 1bdb f7db 83c303 ebc4 }
		$sequence_54 = { 8b9424c8000000 85d2 7421 4533c9 }
		$sequence_55 = { 4883f8ff 488bf8 7445 488d842488000000 }
		$sequence_56 = { 48c7c101000080 ff15???????? 85c0 7568 4c8d8c24d0000000 4c8d8424c8000000 488d542428 }
		$sequence_57 = { 4c8bc3 33d2 ff15???????? 4821742428 4c8d8424c8000000 488d542428 488d4c2450 }
		$sequence_58 = { 4883c208 4983e801 75e4 8b442420 }
		$sequence_59 = { 0f84ca010000 8b424c a801 0f840f010000 8b424c }
		$sequence_60 = { 33c0 89942498000000 899424a8000000 8984249c000000 }
		$sequence_61 = { 498be9 e8???????? 4885c0 488bf0 0f84a3000000 }
		$sequence_62 = { 8db4083089b9ed 57 8d45f4 50 }
		$sequence_63 = { 4d3bef 7415 498bd5 4883c9ff }
		$sequence_64 = { 8b45fc 0fb700 8bc8 81e100f00000 }
		$sequence_65 = { ff75fc e8???????? 8b45f0 40 c745e801000000 }
		$sequence_66 = { 4c8bc6 ff15???????? 488bd8 493bc7 }
		$sequence_67 = { 395d10 0f8402010000 6a03 eb13 3bf3 }
		$sequence_68 = { 6a01 eb3d 3bf3 0f8420010000 }
		$sequence_69 = { 8d85a2fcffff 53 50 895de4 e8???????? }
		$sequence_70 = { 4885c9 7405 e8???????? 4883c428 c3 4053 }
		$sequence_71 = { 493bc5 742f 488d4810 ff15???????? }
		$sequence_72 = { 57 6806020000 668985a0fcffff 8d85a2fcffff 53 }
		$sequence_73 = { 8be5 5d c20400 8325????????00 6a00 }
		$sequence_74 = { 740e 44893d???????? 44893d???????? 488d442440 4c8d4c2440 4c8d442440 4889442430 }
		$sequence_75 = { 89410e 5f 5e 5b c9 c20400 }
		$sequence_76 = { 8bf0 33db 81c1fefeffff 33c0 83cfff 33d2 895dfc }
		$sequence_77 = { 59 c20400 a1???????? 53 55 56 57 }
		$sequence_78 = { 7505 8d5857 eb15 488b05???????? 89702a 48897d00 eb17 }
		$sequence_79 = { eb08 ff15???????? 8bd8 413bde 0f85fb010000 488b05???????? }
		$sequence_80 = { 66b90100 4889442420 e8???????? 3bc3 0f859b000000 }
		$sequence_81 = { a1???????? 83c036 83c9ff f00fc108 }
		$sequence_82 = { 0f8e2a040000 8a05???????? 4238042b 7521 448bc2 4963ce }
		$sequence_83 = { e8???????? 488b0d???????? 448be0 f0834156ff 85c0 }
		$sequence_84 = { 83c036 41 f00fc108 a1???????? 83c01e 50 }
		$sequence_85 = { 488bf0 eb34 488d0595d6ffff 4885c0 7428 }
		$sequence_86 = { 6a0a ff15???????? a1???????? 8b4036 }
		$sequence_87 = { ffb72c080000 e8???????? 5e 5d 5b c3 eb10 }
		$sequence_88 = { e9???????? 83f916 0f8fa7080000 0f8415080000 }
		$sequence_89 = { 83c01e 50 ff15???????? 8a06 3a4704 7311 8b0f }
		$sequence_90 = { 33d2 e8???????? 44892d???????? 33c9 44892d???????? e8???????? 488bcf }
		$sequence_91 = { 8d4604 66d3e0 66098310170000 8d4103 }
		$sequence_92 = { 488b0d???????? 4883c12e ff15???????? 4c8b05???????? 448d7b02 }
		$sequence_93 = { 8b9314170000 83432801 b910000000 8d42f3 2aca }
		$sequence_94 = { a1???????? 8b4c2404 8908 83c01e 50 ff15???????? }
		$sequence_95 = { 83a78c00000000 33c0 c3 51 e8???????? }
		$sequence_96 = { 8b4036 85c0 75ec 8b442404 53 8a1e }
		$sequence_97 = { 5f 5e 5b c20800 51 53 57 }
		$sequence_98 = { e9???????? 83e908 74eb 2bcb 0f84fa000000 2bcb }
		$sequence_99 = { a1???????? 6a00 e8???????? a1???????? 83c01e 50 ff15???????? }
		$sequence_100 = { c3 33c0 483bc8 7458 488b5128 483bd0 }
		$sequence_101 = { c9 c20800 55 8bec 81ec1c010000 8d4807 83e1f8 }
		$sequence_102 = { 5b 8be5 5d c3 0fb708 6683f902 751c }
		$sequence_103 = { 488bd8 488b05???????? f0834056ff 4885db 0f84ec000000 }
		$sequence_104 = { ffd7 8b1d???????? 6a3a b8???????? 56 }
		$sequence_105 = { 48895c2408 57 4883ec30 488bd9 488b0d???????? 488bfa 4883c12e }
		$sequence_106 = { 488b15???????? 4c8d442468 48c7c101000080 ff15???????? }
		$sequence_107 = { 83839c000000ff 397818 0f852ffcffff 33c0 }
		$sequence_108 = { ff35???????? c74424200e440410 c744241c08000000 ffd6 8bf8 }
		$sequence_109 = { e8???????? 8bf0 83fe0c 74c5 3bf3 0f8581020000 a1???????? }
		$sequence_110 = { 8b831c70be03 3305???????? 8b3d???????? 50 33f6 56 8bef }
		$sequence_111 = { c1e804 46 33048d1062be03 85ff }
		$sequence_112 = { 7470 8b3d???????? 56 c7459c44000000 ffd7 8d45e8 50 }
		$sequence_113 = { 397dfc 7417 a1???????? 8b55fc 354c4e4c7e 50 }
		$sequence_114 = { e8???????? 3bc5 89442430 0f84ac010000 53 55 }
		$sequence_115 = { 3934850875be03 742a 8d41ff 85c0 7c10 3934850875be03 7403 }
		$sequence_116 = { 8b30 03f5 85f6 89b31c70be03 740a }
		$sequence_117 = { 68???????? ffd6 a3???????? 33ff 8db7c4260410 }
		$sequence_118 = { ff75ec 8b3d???????? 8bd8 ffd7 ff75e8 ffd7 eb08 }

	condition:
		7 of them and filesize <802816
}