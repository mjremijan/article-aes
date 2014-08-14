/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.ferris.aes.main;

import org.ferris.aes.crypto.AesBase64Wrapper;

/**
 *
 * @author Michael Remijan <mjremijan@yahoo.com> [@mjremijan]
 */
public class Main {
    public static final void main(String [] args) throws Exception
    {
        String encryptMe;
        String encrypted;
        String decrypted;
        
        
        encryptMe = "please encrypt me";
        System.out.printf("encryptMe = %s\n", encryptMe);
        
        encrypted = new AesBase64Wrapper().encryptAndEncode(encryptMe);
        System.out.printf("encrypted = %s\n", encrypted);
        
        decrypted = new AesBase64Wrapper().decodeAndDecrypt(encrypted);
        System.out.printf("decrypted = %s\n", decrypted);

    }
}
