package cz.vaclavtolar.itexttest;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author: Vaclav Tolar, (vaclav_tolar@kb.cz, vaclav.tolar@cleverlance.com, vaclav.tolar@gmail.com)
 * Date: 2016-03-30
 */
public class SignHelloWorld {
    public static final String KEYSTORE = "src/main/resources/pkcs.p12";
    public static final char[] PASSWORD = "Heslo123,".toCharArray();
    public static final String SRC = "src/main/resources/test.pdf";
    public static final String DEST = "src/main/resources/test_signed_%s.pdf";

    public void sign(String src, String dest,
                     Certificate[] chain,
                     PrivateKey pk, String digestAlgorithm, String provider,
                     CryptoStandard subfilter,
                     String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
        // Creating the signature
        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);

//        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        SignHelloWorld app = new SignHelloWorld();
        app.sign(SRC, String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Test 1", "Ghent");
        app.sign(SRC, String.format(DEST, 2), chain, pk, DigestAlgorithms.SHA512, provider.getName(), CryptoStandard.CMS, "Test 2", "Ghent");
        app.sign(SRC, String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CADES, "Test 3", "Ghent");
        app.sign(SRC, String.format(DEST, 4), chain, pk, DigestAlgorithms.RIPEMD160, provider.getName(), CryptoStandard.CADES, "Test 4", "Ghent");
}
}
