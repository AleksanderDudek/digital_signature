import java.security.PrivateKey;
import java.security.Signature;

import iaik.pkcs.pkcs8.PrivateKeyInfo;
import iaik.security.provider.IAIK;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class CertMaker extends JFrame implements ActionListener
{
	// kontrolki appleta
	JTabbedPane tabControl = new JTabbedPane();
	JPanel panel1 = new JPanel();
	JPanel panel2 = new JPanel();
	JPanel panel3 = new JPanel();
//-----------------------------------------------------------
	JTextField jImieNazwisko = new JTextField("Student");
	JLabel lImieNazwisko = new JLabel("Imiê i nazwisko");
	JTextField jDzialOrganizacji = new JTextField("WI");
	JLabel lDzialOrganizacji = new JLabel("Dzia³ organizacji");
	JTextField jNazwaOrganizacji = new JTextField("PS");
	JLabel lNazwaOrganizacji = new JLabel("Nazwa organizacji");
	JTextField jMiasto = new JTextField("Szczecin");
	JLabel lMiasto = new JLabel("Miasto");
	JTextField jWojewodztwo = new JTextField("Zachodniopomorskie");
	JLabel lWojewodztwo = new JLabel("Województwo");
	JTextField jKodPanstwa = new JTextField("PL");
	JLabel lKodPanstwa = new JLabel("Pañstwo");
	JPanel jPanel = new JPanel();
	JLabel lDlugoscKlucza = new JLabel("D³ugoœæ klucza");
	JTextField jDlugoscKlucza = new JTextField("1024");
	JLabel lTypKlucza = new JLabel("Typ klucza");
	JTextField jTypKlucza = new JTextField("RSA");
	JLabel lAlgorytmPodpisu = new JLabel("Algorytm podpisu");
	JTextField jAlgorytmPodpisu = new JTextField("SHA1WithRSA");
	JLabel lOkresWaznosci = new JLabel("Okres wa¿noœci (sek)");
	JTextField jOkresWaznosci = new JTextField("2000000");
	JButton jButton = new JButton("Generuj");
	JTextArea jCertyfikat = new JTextArea();
//-----------------------------------------------------------
	JTextField jWiadomosc = new JTextField("");
	JLabel lWiadomosc = new JLabel("Wiadomoœæ");
	JButton jButton2 = new JButton("Podpisz");
	JLabel lPodpis = new JLabel("Podpis");
	JTextArea jPodpis = new JTextArea();
	JLabel lKluczPryw = new JLabel("Klucz prywatny");
	JTextArea jKluczPryw = new JTextArea();
//-----------------------------------------------------------
	JLabel lWiadomoscOdebrana = new JLabel("Wiadomoœæ");
	JTextField jWiadomoscOdebrana = new JTextField("");
	JLabel lCertyfikatImport = new JLabel("Certyfikat");
	JTextArea jCertyfikatImport = new JTextArea();
	JLabel lPodpisImport = new JLabel("Podpis");
	JTextArea jPodpisImport = new JTextArea();
	JButton jButton3 = new JButton("Weryfikacja");
	JLabel lWynik = new JLabel("");

	public void actionPerformed(ActionEvent e)
	{
		if (e.getSource().equals(jButton))
			try {
				jCertyfikat.setText(GenCert());
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NumberFormatException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (CertificateException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (SignatureException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchProviderException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

		if (e.getSource().equals(jButton2))
			try {
				Podpisz();
//			} catch (iaik.java.security.InvalidKeyException e1) {
			} catch (java.security.InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
//			} catch (iaik.java.security.NoSuchAlgorithmException e1) {
			} catch (java.security.NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
//			} catch (iaik.java.security.SignatureException e1) {
			} catch (java.security.SignatureException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
		if (e.getSource().equals(jButton3))
			try {
				Weryfikacja();
//			} catch (iaik.java.security.InvalidKeyException e1) {
			} catch (java.security.InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
//			} catch (iaik.java.security.cert.CertificateException e1) {
			} catch (java.security.cert.CertificateException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
//			} catch (iaik.java.security.NoSuchAlgorithmException e1) {
			} catch (java.security.NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
//			} catch (iaik.java.security.SignatureException e1) {
			} catch (java.security.SignatureException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	}

	public CertMaker()
	{
		addWindowListener(new WindowAdapter()
		{
			public void windowClosing(WindowEvent e)
			{
				dispose();
				System.exit(0);
			}
		});

		getContentPane().setLayout(null);
	}

	public void init()
	{
		panel1.setLayout(null);
		panel2.setLayout(null);
		panel3.setLayout(null);
		tabControl.setBounds(0,0,getWidth() - 8, getHeight() - 32);
		panel1.setBounds(0,0,tabControl.getWidth(), tabControl.getHeight());
		panel2.setBounds(0,0,tabControl.getWidth(), tabControl.getHeight());
		tabControl.addTab("Generowanie certyfikatu", panel1);
		tabControl.addTab("Podpis", panel2);
		tabControl.addTab("Weryfikacja", panel3);
		getContentPane().add(tabControl);
//-----------------------------------------------------------
		lImieNazwisko.setBounds(0, 0, 150, 20);
		jImieNazwisko.setBounds(150, 0, 200, 20);

		lDzialOrganizacji.setBounds(0, 30, 150, 20);
		jDzialOrganizacji.setBounds(150, 30, 200, 20);

		lNazwaOrganizacji.setBounds(0, 60, 150, 20);
		jNazwaOrganizacji.setBounds(150, 60, 200, 20);

		lMiasto.setBounds(0, 90, 150, 20);
		jMiasto.setBounds(150, 90, 200, 20);

		lWojewodztwo.setBounds(0, 120, 150, 20);
		jWojewodztwo.setBounds(150, 120, 200, 20);

		lKodPanstwa.setBounds(0, 150, 150, 20);
		jKodPanstwa.setBounds(150, 150, 200, 20);

		jPanel.setBounds(0, 180, getWidth(), 2);
		jPanel.setBackground(Color.BLACK);

		lDlugoscKlucza.setBounds(0, 190, 150, 20);
		jDlugoscKlucza.setBounds(150, 190, 200, 20);

		lTypKlucza.setBounds(0, 220, 150, 20);
		jTypKlucza.setBounds(150, 220, 200, 20);

		lAlgorytmPodpisu.setBounds(0, 250, 150, 20);
		jAlgorytmPodpisu.setBounds(150, 250, 200, 20);

		lOkresWaznosci.setBounds(0, 280, 150, 20);
		jOkresWaznosci.setBounds(150, 280, 200, 20);

		jButton.setBounds(getWidth() / 2 - 40, 310, 80, 20);
		jButton.addActionListener(this);

		jCertyfikat.setBounds(4, 340, getWidth() - 20, 196);
//	-----------------------------------------------------------
		lWiadomosc.setBounds(0, 0, 150, 20);
		jWiadomosc.setBounds(150, 0, 200, 20);
		
		jButton2.setBounds(getWidth() / 2 - 40, 30, 80, 20);
		jButton2.addActionListener(this);
		
		lPodpis.setBounds(0, 60, 150, 20);
		jPodpis.setBounds(4, 80, getWidth() - 20, 96);
		
		lKluczPryw.setBounds(0, 180, 150, 20);
		jKluczPryw.setBounds(4, 200, getWidth() - 20, 196);
//	-----------------------------------------------------------
		lWiadomoscOdebrana.setBounds(0, 0, 150, 20);
		jWiadomoscOdebrana.setBounds(150, 0, 200, 20);

		lCertyfikatImport.setBounds(0, 30, 150, 20);
		jCertyfikatImport.setBounds(4, 50, getWidth() - 20, 196);

		lPodpisImport.setBounds(0, 260, 150, 20);
		jPodpisImport.setBounds(4, 280, getWidth() - 20, 96);

		jButton3.setBounds(getWidth() / 2 - 60, 390, 120, 20);
		jButton3.addActionListener(this);
		
		lWynik.setBounds(0, 420, 300, 20);
		
		panel1.add(lImieNazwisko);
		panel1.add(jImieNazwisko);
		panel1.add(lDzialOrganizacji);
		panel1.add(jDzialOrganizacji);
		panel1.add(lNazwaOrganizacji);
		panel1.add(jNazwaOrganizacji);
		panel1.add(lMiasto);
		panel1.add(jMiasto);
		panel1.add(lWojewodztwo);
		panel1.add(jWojewodztwo);
		panel1.add(lKodPanstwa);
		panel1.add(jKodPanstwa);
		panel1.add(jPanel);
		panel1.add(lDlugoscKlucza);
		panel1.add(jDlugoscKlucza);
		panel1.add(lTypKlucza);
		panel1.add(jTypKlucza);
		panel1.add(lAlgorytmPodpisu);
		panel1.add(jAlgorytmPodpisu);
		panel1.add(lOkresWaznosci);
		panel1.add(jOkresWaznosci);
		panel1.add(jButton);
		panel1.add(jCertyfikat);
//	-----------------------------------------------------------
		panel2.add(lWiadomosc);
		panel2.add(jWiadomosc);
		panel2.add(jButton2);
		panel2.add(lPodpis);
		panel2.add(jPodpis);
		panel2.add(lKluczPryw);
		panel2.add(jKluczPryw);
//	-----------------------------------------------------------
		panel3.add(lWiadomoscOdebrana);
		panel3.add(jWiadomoscOdebrana);
		panel3.add(lCertyfikatImport);
		panel3.add(jCertyfikatImport);
		panel3.add(lPodpisImport);
		panel3.add(jPodpisImport);
		panel3.add(jButton3);
		panel3.add(lWynik);
	}

	private String GenCert() throws NoSuchAlgorithmException, InvalidKeyException, IOException, NumberFormatException, CertificateException, SignatureException, NoSuchProviderException
	{
		// implementacja generowania certyfikatu

				//generowanie pary kluczy
				CertAndKeyGen paraKluczy = new CertAndKeyGen (jTypKlucza.getText(), jAlgorytmPodpisu.getText());
				
				//dla podanych parametrow i dlugosci klucza generuje pare wewnatrz obiektu paraKluczy
				paraKluczy.generate(Integer.parseInt(jDlugoscKlucza.getText()));
				
				// albo = albo jakies .add; zwraca klucz, a potem koduje i zapisuje do pola jKluczPryw
				
				PrivateKey priv = paraKluczy.getPrivateKey();
				
				//inicjalizacja obiektu klasy X500Name
				X500Name cert = new X500Name(jImieNazwisko.getText(),jDzialOrganizacji.getText(),
							jNazwaOrganizacji.getText(),jMiasto.getText(), jWojewodztwo.getText(),
							jKodPanstwa.getText());
				
				
				
				
				//zwraca certyfikat do pola tekstowego
				BASE64Encoder encoder = new BASE64Encoder();
				//return null;
				
				X509Certificate certyfikat = paraKluczy
						.getSelfCertificate(cert, Long.parseLong(jOkresWaznosci.getText()
								)
								);
				
				jKluczPryw.setText(Base64.encode(paraKluczy.getPrivateKey().getEncoded()));
				jCertyfikatImport.setText(Base64.encode(certyfikat.getEncoded()));
				
				return  Base64.encode(certyfikat.getEncoded());
	}
	
	private void Podpisz() throws IOException, java.security.InvalidKeyException, java.security.NoSuchAlgorithmException, java.security.SignatureException
	{
		// implementacja podpisu wiadomosci

				//obiekt dekodujacy
				BASE64Decoder decoder = new BASE64Decoder();
				BASE64Encoder encoder = new BASE64Encoder();

	
				//odtworzenie klucza?
//				PrivateKeyInfo
//				.getPrivateKey(decoder
//						.decodeBuffer(jKluczPryw
//								.getText()));
//				
				
				PrivateKey mpk = PrivateKeyInfo.getPrivateKey(decoder
						.decodeBuffer(jKluczPryw
								.getText()));
				//interfejs Signature
				Signature sig = Signature.getInstance(jAlgorytmPodpisu.getText());;
					
				
				sig.initSign(mpk);
										
				byte [] message = decoder.decodeBuffer(jWiadomosc.getText());
				sig.update(message);
				
				byte [] eSign = sig.sign();

				//wpisanie Base64 do pola podpis
				jPodpis.setText(  encoder.encode(eSign));
				jPodpisImport.setText( encoder.encode(eSign));
	}

	private void Weryfikacja() throws IOException, java.security.InvalidKeyException, java.security.NoSuchAlgorithmException, java.security.SignatureException, java.security.cert.CertificateException
	{
		// implementacja weryfikacji podpisu
		BASE64Decoder decoder = new BASE64Decoder();
		
		
		//odtworzenie certyfikatu
		iaik.x509.X509Certificate cert =  new iaik.x509.X509Certificate(decoder.decodeBuffer(jCertyfikatImport.getText()));
		
		//pobranie klucza publicznego, pobranie algorytmu
		Signature sig = Signature.getInstance(jAlgorytmPodpisu.getText());
		
		//weryfikacja, pobranie klucza publicznego
		sig.initVerify(cert.getPublicKey());
		
		//przekazanie wiadomoœci do obiektu podpisu
		sig.update(decoder.decodeBuffer(jWiadomoscOdebrana.getText()));

		byte [] decodedSig = decoder.decodeBuffer(jPodpisImport.getText());
		
		boolean verify = sig.verify(decodedSig);
		
		if(verify == true)
		{
			//true
			lWynik.setText("OK");
		}
		else
		{
		  //false
			lWynik.setText("B³¹d");

		}
		
		
	}

	public static void main(String args[])
	{
		IAIK.addAsProvider(true);
		CertMaker w = new CertMaker();
		w.setSize(400, 600);
		w.setTitle("CertMaker");
		w.setLocation(100, 0);
		w.init();
		w.setVisible(true);
		w.invalidate();
	}
}