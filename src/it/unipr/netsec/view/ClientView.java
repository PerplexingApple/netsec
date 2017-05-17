package it.unipr.netsec.view;


import it.unipr.netsec.client.Client;
import it.unipr.netsec.crypto.DesCrypt;
import it.unipr.netsec.server.SocketUtil;
import it.unipr.netsec.util.ByteFunc;
import it.unipr.netsec.util.Message;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;


public class ClientView extends JPanel implements ActionListener {
	private static final int TEXT_HEIGHT = 10;
	private static final int Width = 30;
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final Logger LOGGER = Logger.getLogger( ClientView.class.getName() );
	

	private final static String newline = "\n";
	
	SecretKey aliceDesKey;
	ObjectOutputStream out;
	JTextField textField;
	JTextArea textArea;

	public ClientView(ObjectOutputStream out, SecretKey aliceDesKey) {		
		super(new GridBagLayout());
		
		LOGGER.log(Level.INFO, "Constructing view... ");
		createPanels();
		
		this.aliceDesKey = aliceDesKey;
		this.out = out;
	}
	
	public void createPanels(){
		LOGGER.log(Level.INFO, "Constructing panels... ");
		textField = new JTextField(Width);
		textField.addActionListener(this);

		textArea = new JTextArea(TEXT_HEIGHT, Width);
		textArea.setEditable(false);

		JScrollPane scrollPane = new JScrollPane(textArea);

		//Add Components to this panel.
		GridBagConstraints c = new GridBagConstraints();
		c.gridwidth = GridBagConstraints.REMAINDER;

		c.fill = GridBagConstraints.HORIZONTAL;
		add(textField, c);

		c.fill = GridBagConstraints.BOTH;
		c.weightx = 1.0;
		c.weighty = 1.0;
		add(scrollPane, c) ;
	}
	
	public void updateText(String text) throws IOException{
		LOGGER.log(Level.INFO, "TextArea is writing a message... ");

		textArea.append(text + newline);
        textField.selectAll(); 

        //Make sure the new text is visible
        textArea.setCaretPosition(textArea.getDocument().getLength());
        
	}
	
	
    /**
     * Create the GUI and show it.
     */
    private void createAndShowGUI() {
    	//Create and set up the window.
        JFrame frame = new JFrame("Chat Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        //Add contents to the window.
        frame.add( this );

        //Display the window.
        frame.pack();
        frame.setVisible(true);
    }

    public void show() {
        //Schedule a job for the event-dispatching thread
        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                createAndShowGUI();
            }
        });
    }



	@Override
	public void actionPerformed(ActionEvent e) {
		try {
			String text = textField.getText();
			byte[] plaintext =  text.getBytes();
			byte[] crypted = DesCrypt.encrypt( plaintext, aliceDesKey);
			
			//updateText(text);	
			
			textField.setText("");	
		
			SocketUtil.send( new Message(crypted), out);
		} catch (IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e1) {
			LOGGER.log(Level.SEVERE, e1.toString());
		}

	}
}