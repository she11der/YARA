import "pe"

rule SIGNATURE_BASE_HKTL_Imphashes_Aug22_1 : FILE
{
	meta:
		description = "Detects different hacktools based on their imphash"
		author = "Florian Roth"
		id = "e1d4dde6-16ad-5495-b3a7-01a86c830761"
		date = "2022-08-17"
		modified = "2023-03-21"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_imphash_detection.yar#L93-L192"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e76701b889138f9635cfe3a2f08710db3a6f0a3c3a15faa705ff0904d0566a1f"
		score = 80
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and (pe.imphash()=="bcca3c247b619dcd13c8cdff5f123932" or pe.imphash()=="3a19059bd7688cb88e70005f18efc439" or pe.imphash()=="bf6223a49e45d99094406777eb6004ba" or pe.imphash()=="0c106686a31bfe2ba931ae1cf6e9dbc6" or pe.imphash()=="0d1447d4b3259b3c2a1d4cfb7ece13c3" or pe.imphash()=="1b0369a1e06271833f78ffa70ffb4eaf" or pe.imphash()=="4c1b52a19748428e51b14c278d0f58e3" or pe.imphash()=="4d927a711f77d62cebd4f322cb57ec6f" or pe.imphash()=="66ee036df5fc1004d9ed5e9a94a1086a" or pe.imphash()=="672b13f4a0b6f27d29065123fe882dfc" or pe.imphash()=="6bbd59cea665c4afcc2814c1327ec91f" or pe.imphash()=="725bb81dc24214f6ecacc0cfb36ad30d" or pe.imphash()=="9528a0e91e28fbb88ad433feabca2456" or pe.imphash()=="9da6d5d77be11712527dcab86df449a3" or pe.imphash()=="a6e01bc1ab89f8d91d9eab72032aae88" or pe.imphash()=="b24c5eddaea4fe50c6a96a2a133521e4" or pe.imphash()=="d21bbc50dcc169d7b4d0f01962793154" or pe.imphash()=="fcc251cceae90d22c392215cc9a2d5d6" or pe.imphash()=="23867a89c2b8fc733be6cf5ef902f2d1" or pe.imphash()=="a37ff327f8d48e8a4d2f757e1b6e70bc" or pe.imphash()=="f9a28c458284584a93b14216308d31bd" or pe.imphash()=="6118619783fc175bc7ebecff0769b46e" or pe.imphash()=="959a83047e80ab68b368fdb3f4c6e4ea" or pe.imphash()=="563233bfa169acc7892451f71ad5850a" or pe.imphash()=="87575cb7a0e0700eb37f2e3668671a08" or pe.imphash()=="13f08707f759af6003837a150a371ba1" or pe.imphash()=="1781f06048a7e58b323f0b9259be798b" or pe.imphash()=="233f85f2d4bc9d6521a6caae11a1e7f5" or pe.imphash()=="24af2584cbf4d60bbe5c6d1b31b3be6d" or pe.imphash()=="632969ddf6dbf4e0f53424b75e4b91f2" or pe.imphash()=="713c29b396b907ed71a72482759ed757" or pe.imphash()=="749a7bb1f0b4c4455949c0b2bf7f9e9f" or pe.imphash()=="8628b2608957a6b0c6330ac3de28ce2e" or pe.imphash()=="8b114550386e31895dfab371e741123d" or pe.imphash()=="94cb940a1a6b65bed4d5a8f849ce9793" or pe.imphash()=="9d68781980370e00e0bd939ee5e6c141" or pe.imphash()=="b18a1401ff8f444056d29450fbc0a6ce" or pe.imphash()=="cb567f9498452721d77a451374955f5f" or pe.imphash()=="730073214094cd328547bf1f72289752" or pe.imphash()=="17b461a082950fc6332228572138b80c" or pe.imphash()=="dc25ee78e2ef4d36faa0badf1e7461c9" or pe.imphash()=="819b19d53ca6736448f9325a85736792" or pe.imphash()=="829da329ce140d873b4a8bde2cbfaa7e" or pe.imphash()=="c547f2e66061a8dffb6f5a3ff63c0a74" or pe.imphash()=="0588081ab0e63ba785938467e1b10cca" or pe.imphash()=="0d9ec08bac6c07d9987dfd0f1506587c" or pe.imphash()=="bc129092b71c89b4d4c8cdf8ea590b29" or pe.imphash()=="4da924cf622d039d58bce71cdf05d242" or pe.imphash()=="e7a3a5c377e2d29324093377d7db1c66" or pe.imphash()=="9a9dbec5c62f0380b4fa5fd31deffedf" or pe.imphash()=="af8a3976ad71e5d5fdfb67ddb8dadfce" or pe.imphash()=="0c477898bbf137bbd6f2a54e3b805ff4" or pe.imphash()=="0ca9f02b537bcea20d4ea5eb1a9fe338" or pe.imphash()=="3ab3655e5a14d4eefc547f4781bf7f9e" or pe.imphash()=="e6f9d5152da699934b30daab206471f6" or pe.imphash()=="3ad59991ccf1d67339b319b15a41b35d" or pe.imphash()=="ffdd59e0318b85a3e480874d9796d872" or pe.imphash()=="0cf479628d7cc1ea25ec7998a92f5051" or pe.imphash()=="07a2d4dcbd6cb2c6a45e6b101f0b6d51" or pe.imphash()=="d6d0f80386e1380d05cb78e871bc72b1" or pe.imphash()=="38d9e015591bbfd4929e0d0f47fa0055" or pe.imphash()=="0e2216679ca6e1094d63322e3412d650" or pe.imphash()=="ada161bf41b8e5e9132858cb54cab5fb" or pe.imphash()=="2a1bc4913cd5ecb0434df07cb675b798" or pe.imphash()=="11083e75553baae21dc89ce8f9a195e4" or pe.imphash()=="a23d29c9e566f2fa8ffbb79267f5df80" or pe.imphash()=="4a07f944a83e8a7c2525efa35dd30e2f" or pe.imphash()=="767637c23bb42cd5d7397cf58b0be688" or pe.imphash()=="14c4e4c72ba075e9069ee67f39188ad8" or pe.imphash()=="3c782813d4afce07bbfc5a9772acdbdc" or pe.imphash()=="7d010c6bb6a3726f327f7e239166d127" or pe.imphash()=="89159ba4dd04e4ce5559f132a9964eb3" or pe.imphash()=="6f33f4a5fc42b8cec7314947bd13f30f" or pe.imphash()=="5834ed4291bdeb928270428ebbaf7604" or pe.imphash()=="5a8a8a43f25485e7ee1b201edcbc7a38" or pe.imphash()=="dc7d30b90b2d8abf664fbed2b1b59894" or pe.imphash()=="41923ea1f824fe63ea5beb84db7a3e74" or pe.imphash()=="3de09703c8e79ed2ca3f01074719906b" or pe.imphash()=="a53a02b997935fd8eedcb5f7abab9b9f" or pe.imphash()=="e96a73c7bf33a464c510ede582318bf2" or pe.imphash()=="32089b8851bbf8bc2d014e9f37288c83" or pe.imphash()=="09D278F9DE118EF09163C6140255C690" or pe.imphash()=="03866661686829d806989e2fc5a72606" or pe.imphash()=="e57401fbdadcd4571ff385ab82bd5d6d" or pe.imphash()=="84B763C45C0E4A3E7CA5548C710DB4EE" or pe.imphash()=="19584675d94829987952432e018d5056" or pe.imphash()=="330768a4f172e10acb6287b87289d83b")
}
