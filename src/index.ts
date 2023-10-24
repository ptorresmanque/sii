import os from 'os';
if (os.platform() == 'win32') {  
    if (os.arch() == 'ia32') {
        var chilkat = require('@chilkat/ck-node11-win-ia32');
    } else {
        var chilkat = require('@chilkat/ck-node18-win64'); 
    }
} else if (os.platform() == 'linux') {
    if (os.arch() == 'arm') {
        var chilkat = require('@chilkat/ck-node11-arm');
    } else if (os.arch() == 'x86') {
        var chilkat = require('@chilkat/ck-node11-linux32');
    } else {
        var chilkat = require('@chilkat/ck-node11-linux64');
    }
} else if (os.platform() == 'darwin') {
    var chilkat = require('@chilkat/ck-node11-macosx');
}

function chilkatExample() {

    // This example assumes the Chilkat API to have been previously unlocked.
    // See Global Unlock Sample for sample code.

    // See: Apply 2nd Signature to sii.cl Factura Electr�nica (Chile Servicio de Impuestos Internos)
    // for an example showing how to apply a 2nd signature.

    // We want to sign XML that looks like the following:

    // <?xml version="1.0" encoding="iso-8859-1"?>
    // <DTE version="1.0" xmlns="http://www.sii.cl/SiiDte">
    //     <Documento ID="F13T34">
    //         <Encabezado>
    //             <IdDoc>
    //                 <TipoDTE>34</TipoDTE>
    //                 <Folio>13</Folio>
    //                 <FchEmis>2020-07-17</FchEmis>
    //                 <FmaPago>1</FmaPago>
    //                 <FchVenc>2020-07-17</FchVenc>
    //             </IdDoc>
    //             <Emisor>
    //                 <RUTEmisor>...</RUTEmisor>
    //                 <RznSoc>...</RznSoc>
    //                 <GiroEmis>...</GiroEmis>
    //                 <Acteco>...</Acteco>
    //                 <DirOrigen>...</DirOrigen>
    //                 <CmnaOrigen>...</CmnaOrigen>
    //                 <CiudadOrigen>...</CiudadOrigen>
    //             </Emisor>
    //             <Receptor>
    //                 <RUTRecep>...</RUTRecep>
    //                 <RznSocRecep>...</RznSocRecep>
    //                 <GiroRecep>...</GiroRecep>
    //                 <Contacto/>
    //                 <DirRecep>...</DirRecep>
    //                 <CmnaRecep>...</CmnaRecep>
    //                 <CiudadRecep>...</CiudadRecep>
    //             </Receptor>
    //             <Totales>
    //                 <MntExe>14999</MntExe>
    //                 <MntTotal>14999</MntTotal>
    //             </Totales>
    //         </Encabezado>
    //         <Detalle>
    //             <NroLinDet>1</NroLinDet>
    //             <CdgItem>
    //                 <TpoCodigo>INT</TpoCodigo>
    //                 <VlrCodigo>1</VlrCodigo>
    //             </CdgItem>
    //             <NmbItem>Atencin profesional mes de Junio 2020</NmbItem>
    //             <QtyItem>1</QtyItem>
    //             <UnmdItem>UNI</UnmdItem>
    //             <PrcItem>14999</PrcItem>
    //             <MontoItem>14999</MontoItem>
    //         </Detalle>
    //         <TED version="1.0">
    //             <DD>
    //                 <RE>99972220-K</RE>
    //                 <TD>34</TD>
    //                 <F>13</F>
    //                 <FE>2020-07-17</FE>
    //                 <RR>99942999-2</RR>
    //                 <RSR>...</RSR>
    //                 <MNT>14999</MNT>
    //                 <IT1>Atencion profesional mes de Junio 2020</IT1>
    //                 <CAF version="1.0">
    //                     <DA>
    //                         <RE>99972220-K</RE>
    //                         <RS>...</RS>
    //                         <TD>34</TD>
    //                         <RNG>
    //                             <D>3</D>
    //                             <H>12</H>
    //                         </RNG>
    //                         <FA>2019-10-10</FA>
    //                         <RSAPK>
    //                             <M>2zHVYpcVNQRvS2yFuqdrh...TEQZx/m0t9HVTgWKZvlc6LSQ==</M>
    //                             <E>Aw==</E>
    //                         </RSAPK>
    //                         <IDK>300</IDK>
    //                     </DA>
    //                     <FRMA algoritmo="SHA1withRSA">LaVkjISGu...sBtsQL1jR9lw==</FRMA>
    //                 </CAF>
    //                 <TSTED>2020-07-17T13:19:10</TSTED>
    //             </DD>
    //             <FRMT algoritmo="SHA1withRSA">LxZr6zmXRZIfTz7...IXS6sp4vfz2fIsA==</FRMT>
    //         </TED>
    //         <TmstFirma>2020-07-17T13:19:10</TmstFirma>
    //     </Documento>
    // </DTE>

    var success = true;

    var gen = new chilkat.XmlDSigGen();

    gen.SigLocation = "DTE";
    gen.SigLocationMod = 0;
    gen.SigNamespacePrefix = "";
    gen.SigNamespaceUri = "http://www.w3.org/2000/09/xmldsig#";
    gen.SignedInfoCanonAlg = "C14N";
    gen.SignedInfoDigestMethod = "sha1";

    // -------- Reference 1 --------
    gen.AddSameDocRef("F13T34","sha1","","","");

    // Provide a certificate + private key. (PFX password is test123)
    var cert = new chilkat.Cert();
    success = cert.LoadPfxFile("src/assets/Certificado.pfx","Plukas010765*");
    if (success !== true) {
        console.error(cert.LastErrorText);
        return;
    }

    gen.SetX509Cert(cert,true);

    gen.KeyInfoType = "X509Data+KeyValue";
    gen.X509Type = "Certificate";

    // Load XML to be signed...
    var sbXml = new chilkat.StringBuilder();
    success = sbXml.LoadFile("src/assets/boleta.xml","iso-8859-1");
    if (success == false) {
        console.log("Failed to load XML file.");
        return;
    }

    gen.Behaviors = "IndentedSignature";

    // Sign the XML...
    success = gen.CreateXmlDSigSb(sbXml);
    if (success !== true) {
        console.log(gen.LastErrorText);
        return;
    }

    // -----------------------------------------------

    // Save the signed XML to a file.
    success = sbXml.WriteFile("src/assets/signed1.xml","iso-8859-1",false);

    console.log(sbXml.GetAsString());

    // ----------------------------------------
    // Verify the signatures we just produced...
    var verifier = new chilkat.XmlDSig();
    success = verifier.LoadSignatureSb(sbXml);
    if (success !== true) {
        console.log(verifier.LastErrorText);
        return;
    }

    var numSigs = verifier.NumSignatures;
    var verifyIdx = 0;
    while (verifyIdx < numSigs) {
        verifier.Selector = verifyIdx;
        var verified = verifier.VerifySignature(true);
        if (verified !== true) {
            console.log(verifier.LastErrorText);
            return;
        }

        verifyIdx = verifyIdx+1;
    }

    console.log("All signatures were successfully verified.");

}

chilkatExample();