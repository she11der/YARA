rule MALPEDIA_Win_Bazarbackdoor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5d2ecc0c-54dd-5654-9202-132113260f24"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bazarbackdoor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bazarbackdoor_auto.yar#L1-L638"
		license_url = "N/A"
		logic_hash = "bfaa99dbae5ad02f0954740ed30f16e2a148a8070db46fd5f787ce6fb0204c77"
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
		$sequence_0 = { 488bce 4889442420 ff15???????? 85c0 780a }
		$sequence_1 = { 488bce ffd0 eb03 488bc3 }
		$sequence_2 = { b803000000 e9???????? 488b5568 4c8d85f0040000 488b4c2450 bb08000000 }
		$sequence_3 = { e9???????? 488b4c2458 488d55e0 ff15???????? }
		$sequence_4 = { 4533c0 c744242002000000 ba00000040 ffd0 }
		$sequence_5 = { 0fb70f ff15???????? 0fb74f02 0fb7d8 ff15???????? }
		$sequence_6 = { 488d4d80 e8???????? 498bd6 488d4d80 }
		$sequence_7 = { 7507 33c0 e9???????? b8ff000000 }
		$sequence_8 = { 0fb7d8 ff15???????? 0fb74f08 440fb7e8 }
		$sequence_9 = { 4885c9 7406 488b11 ff5210 ff15???????? }
		$sequence_10 = { e8???????? cc e8???????? cc 4053 4883ec20 b902000000 }
		$sequence_11 = { c3 0fb74c0818 b80b010000 663bc8 }
		$sequence_12 = { e8???????? 4c89e1 e8???????? 8b05???????? }
		$sequence_13 = { 4533c9 4889442428 488d95a0070000 488d442470 41b80f100000 }
		$sequence_14 = { 0fb6c9 4881e9c0000000 48c1e108 4803c8 8bc1 488d94059f070000 }
		$sequence_15 = { 31ff 4889c1 31d2 4989f0 }
		$sequence_16 = { 4889f1 e8???????? 8b05???????? 8b0d???????? }
		$sequence_17 = { 4c89742440 4c89742438 4489742430 4c89742428 }
		$sequence_18 = { ff15???????? 4889c1 31d2 4d89e0 }
		$sequence_19 = { 418d5508 488bc8 ff15???????? 488bd8 }
		$sequence_20 = { e8???????? 4889c7 8b05???????? 8b0d???????? }
		$sequence_21 = { 488d9590050000 488bce ff15???????? 85c0 }
		$sequence_22 = { 488d442470 41b80f100000 488bce 4889442420 }
		$sequence_23 = { ff15???????? ff15???????? 4d8bc5 33d2 488bc8 }
		$sequence_24 = { 0fafc8 89c8 83f0fe 85c8 0f95c0 0f94c3 }
		$sequence_25 = { c744242003000000 4889f9 ba00000080 41b801000000 }
		$sequence_26 = { c744242800000001 4533c9 4533c0 c744242002000000 ba1f000f00 }
		$sequence_27 = { 83fe09 0f9fc2 83fe0a 0f9cc1 }
		$sequence_28 = { 4889442428 488d95b0030000 488d4580 41b80f100000 }
		$sequence_29 = { 4d8bc7 33d2 488bc8 ff15???????? ff15???????? }
		$sequence_30 = { 08ca 80f201 7502 ebfe }
		$sequence_31 = { 48c744243000000000 c744242880000000 c744242003000000 4889f9 }
		$sequence_32 = { 0f94c3 83f809 0f9fc2 83f80a 0f9cc0 30d8 }
		$sequence_33 = { 0fb65305 33c0 80f973 0f94c0 }
		$sequence_34 = { 0f9fc1 83fa0a 0f9cc2 30da 08c1 80f101 08d1 }
		$sequence_35 = { 7528 0fb64b04 0fb6d1 80f973 }
		$sequence_36 = { 4889c1 31d2 4989f8 ff15???????? 4885c0 }
		$sequence_37 = { ff15???????? 31ed 4889c1 31d2 4989d8 }
		$sequence_38 = { 488bd3 e8???????? ff15???????? 4c8bc3 33d2 }
		$sequence_39 = { 0fb6d1 80f973 7504 0fb65305 }
		$sequence_40 = { 08c1 80f101 7502 ebfe }
		$sequence_41 = { e8???????? 4889f9 4889f2 ffd0 }
		$sequence_42 = { 0f9cc2 30da 7509 08c1 }
		$sequence_43 = { 85da 0f94c3 83fd0a 0f9cc2 }
		$sequence_44 = { 84d2 7405 80fa2e 750f }
		$sequence_45 = { 4889c1 31d2 4d89e8 ff15???????? }
		$sequence_46 = { 4889c1 31d2 4d89f8 ffd3 }
		$sequence_47 = { e8???????? 4c897c2420 4889d9 89fa }
		$sequence_48 = { 89f0 4883c450 5b 5f }
		$sequence_49 = { 8d4833 ff15???????? c744242810000000 4533c9 }
		$sequence_50 = { 6a00 56 ff15???????? 5f 5e 5d 8bc3 }
		$sequence_51 = { 689c7d9d93 6a04 5a e8???????? 59 59 85c0 }
		$sequence_52 = { 8d44244c 50 6a00 ff74243c 53 55 ff15???????? }
		$sequence_53 = { 6685ff 0f849c000000 837c2460ff 0f858c000000 }
		$sequence_54 = { 50 0fb745e8 50 68???????? e8???????? }
		$sequence_55 = { 66890d???????? 0fb7ca ff15???????? b901000000 66c746020100 668906 }
		$sequence_56 = { 7506 8b0e 894c2460 0fb7c0 }
		$sequence_57 = { 8a842483030000 81fe80000000 760b 24f2 0c02 }
		$sequence_58 = { 57 8d4101 6a0e 8bf0 5f 8a11 }
		$sequence_59 = { 7406 6a35 ffd0 eb02 33c0 }
		$sequence_60 = { ffd6 8d7001 56 6a08 ff15???????? 50 }
		$sequence_61 = { 740d 33d2 83f902 0f95c2 83c224 }
		$sequence_62 = { 0f95c2 83c224 eb05 ba29000000 }
		$sequence_63 = { 660f73d801 660febd0 660f7ed0 84c0 }
		$sequence_64 = { 750b 8ac1 2ac2 fec8 88041a }
		$sequence_65 = { 8d4701 84c9 0f45c7 803a00 8bf8 }
		$sequence_66 = { 6a00 6a00 50 8d4601 }
		$sequence_67 = { c1f808 0fb6c0 50 0fb6c2 }
		$sequence_68 = { 83c410 b800308804 6a00 50 }
		$sequence_69 = { 81feff030000 733c 8a02 3cc0 721e 0fb6c8 }
		$sequence_70 = { 89542410 48894c2408 4883ec48 8b442458 89442424 48c744242800000000 }
		$sequence_71 = { 488b442430 488b8c2410010000 48894830 488b442430 488b8c2418010000 48894838 488b442430 }
		$sequence_72 = { 488bca 448bc0 488bd1 488b4c2430 e8???????? 488b442428 }
		$sequence_73 = { ff15???????? 33c0 eb47 488b442430 8b4014 }
		$sequence_74 = { 4825ffff0000 488b8c2488000000 4c8b4140 488bd0 }
		$sequence_75 = { 488b442430 48c7404800000000 488b442430 eb14 }
		$sequence_76 = { eb1f 488b442430 8b4024 2580000000 }
		$sequence_77 = { 488b442458 488b00 b908000000 486bc909 488d840888000000 4889442428 488b442428 }

	condition:
		7 of them and filesize <2088960
}
