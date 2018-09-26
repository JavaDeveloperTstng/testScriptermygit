/*
 * Copyright 2014 - 2017 Cognizant Technology Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cognizant.cognizantits.engine.commands;

import com.cognizant.cognizantits.datalib.testdata.view.TestDataView;
import com.cognizant.cognizantits.engine.constants.ObjectProperty;
import com.cognizant.cognizantits.engine.constants.SystemDefaults;
import com.cognizant.cognizantits.engine.core.CommandControl;
import com.cognizant.cognizantits.engine.execution.exception.UnCaughtException;
import com.cognizant.cognizantits.engine.support.Status;
import com.cognizant.cognizantits.engine.support.methodInf.Action;
import com.cognizant.cognizantits.engine.support.methodInf.InputType;
import com.cognizant.cognizantits.engine.support.methodInf.ObjectType;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;

import javax.crypto.Cipher;

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

import sun.misc.*;

import java.util.Iterator;

import org.apache.commons.codec.binary.Base64;
import java.io.InputStream;

public class Unix extends General {
    // create your own function

    public Unix(CommandControl cc) {
        super(cc);
    }

    //public Unix prTest = new Unix();
	static Session session = null;
	static Boolean connectStatus;
	String sDataParam1 = userData.getData("UNIX", "UnixHost","1", "1");
	String sDataParam2 = userData.getData("UNIX", "UnixUserID","1", "1");
	//String sDataParam3 = getVar("%Password");
	String sDataParam4 = userData.getData("UNIX", "UnixPassword","1", "1");
	
	private static String algorithm = "AES";
    private static byte[] keyValue=new byte[] {'0','2','3','4','5','6','7','8','9','1','2','3','4','5','6','7'};// your key
    
    @Action(object = ObjectType.ANY, desc = "Establish connection to UNIX, Ensure to add #UnixHost, #UnixUserID, #UnixPassword to Global datasheet with same column names by removing prefix, reference this global data to test data sheet UNIX in iteration 1 and subiteration 1")
	public void connectUnixSession(){
        boolean connStatus = false;
        try {
            //nUser = user;
            //String privateKey = "src/test/resources/Keys/" + envPRC + "/id_rsa";
            //privateKeyPath = Paths.get(privateKey);
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            config.put("PreferredAuthentications", "password");
            JSch jsch = new JSch();
            //System.out.println(sDataParam1);
            //System.out.println(sDataParam2);
            //System.out.println(sDataParam3);
            //System.out.println(sDataParam4);
            session = jsch.getSession(sDataParam2, sDataParam1, 22);
            //session = jsch.getSession(sDataParam2);
            
            //session.setPassword(decrypt(sDataParam4));
            session.setPassword(decrypt(sDataParam4));
            session.setConfig(config);
            session.connect(60000);
            connStatus = true;
            System.out.println("Session Connected");
            Report.updateTestLog("UNIX Session Connected to Host", sDataParam1, Status.PASS);
            Thread.sleep(2000);

        }catch (Exception ex) {
        	System.out.println("Raising Exception..");
        	Report.updateTestLog("Session not Connected to Host", sDataParam1, Status.FAIL);
            ex.printStackTrace();
        }
        System.out.println("UNIX Session Connected: " + connStatus);
        //return connStatus;
    }
	
	// Performs decryption
/*    public String decrypt(String encryptedText) throws Exception
    {
        // generate key
        Key key = generateKey();
        Cipher chiper = Cipher.getInstance(algorithm);
        chiper.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
        byte[] decValue = chiper.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }
    
  //generateKey() is used to generate a secret key for AES algorithm
    private Key generateKey() throws Exception
    {
        Key key = new SecretKeySpec(keyValue, algorithm);
        return key;
    }*/
    
    public static String decrypt(String v) {
		if (isEnc(v)) {
			v = v.replaceFirst("TMENC:", "");
			return doDecrypt(v);
		} else if (v.matches(".* Enc")){
			v = v.substring(0, v.lastIndexOf(" Enc"));
            byte[] valueDecoded = Base64.decodeBase64(v);
            v = new String(valueDecoded);
            return v;
		}
		else {
			return v;
		}
	}
    
    public static boolean isEnc(String v) {
		return v != null && v.startsWith("TMENC:");
	}
    
    private static String doDecrypt(String v) {
        // do implement ur owm crypto
        return new String(Base64.decodeBase64(v));
    }
    
    @Action(object = ObjectType.ANY, desc = "Run and validate a command in UNIX, Provide command to be executed in UNIX sheet under column name UnixCommand and output to be validated in column name UnixValidate")
    public void runAndValidateUnixCommand() throws Exception{
    	String unixCommand = userData.getData("UNIX", "UnixCommand");
    	String unixValidate = userData.getData("UNIX", "UnixValidate");
    	
    	Channel channel = session.openChannel("exec");
        ((ChannelExec)channel).setCommand(unixCommand);
        InputStream in = channel.getInputStream();
        channel.connect();
        byte[] tmp = new byte[1024];
        while(true){
        	while(in.available()>0){
        		int i = in.read(tmp,0,1024);
        		if(i<0)break;
        		String value = new String (tmp,0,i);
        		if(value.contains(unixValidate)){
        			System.out.print(new String (tmp,0,i));
        			Report.updateTestLog("UNIX Command executed succssfully", unixValidate, Status.PASS);
        			userData.putData("UNIX", "UnixOutput", value);
        		}
        		else{
        			System.out.print(new String (tmp,0,i));
        			Report.updateTestLog("UNIX Command did not executed succssfully", value, Status.FAIL);
        		}
        		
        	}
        	if(channel.isClosed()){
        		System.out.println("Exit Status : "+channel.getExitStatus());
        		Report.updateTestLog("UNIX Channel for command execution ended", "Channel ended in UNIX", Status.PASS);
        		break;
        	}
        	try{Thread.sleep(1000);}catch(Exception ee){}
        }
    }
    
    
    @Action(object = ObjectType.ANY, desc = "Disconnect session to UNIX")
    public void disconnectUnixSession() throws Exception{
    	//channel.disconnect();
        session.disconnect();
        System.out.println("Session Disconnected");
        Report.updateTestLog("Session Disconnected from Host", sDataParam1, Status.PASS);
    }
}
