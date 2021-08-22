
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import com.alibaba.fastjson.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;


import javax.crypto.Cipher;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;


public class API {
    private static   String theurl="http://127.0.0.1:18080";
    private static   PublicKey PUK=null;
//    public static void main(String[] args) throws Exception {
//
////        System.out.println(System.getProperty(
////                "user.dir"
////        ));
//        RSAInit();
//
//        JSONObject res_json=Testget(theurl);
//        System.out.println(res_json.toJSONString());
//
////        FileInputStream fs=new FileInputStream("D:\\public.pem");
////        byte[] buffer=new byte[fs.available()];
////        fs.read(buffer);
////        fs.close();
////
////        FileInputStream fs2=new FileInputStream("D:\\private.pem");
////        byte[] buffer2=new byte[fs2.available()];
////        fs2.read(buffer2);
////        fs2.close();
////        System.out.println(new String(buffer));
////        PublicKey puk= RSAUtil.getRSAPublicKey(new String(buffer));
////        PrivateKey pak= RSAUtil.getRSAPrivateKey(new String(buffer2));
////        String message = "江湖人称猛梁君";
////        System.out.println("随机生成的公钥为:" + StringUtils.newStringUtf8(Base64.encodeBase64(puk.getEncoded())));
////        System.out.println("随机生成的私钥为:" +  StringUtils.newStringUtf8(Base64.encodeBase64(pak.getEncoded())));
////        String messageEn = encrypt(message,puk);
////        System.out.println(message + "\t加密后的字符串为:" + messageEn);
////        String messageDe = decrypt(messageEn,pak);
////        System.out.println("还原后的字符串为:" + messageDe);
//
//
//        //这个是AdminCreateNFT请求的函数名称,被加密混淆了
//        String AdminCreateNFTactionName  = "593b8e9e27c1b29a93094f094c5c17b427e0b4efe34ae69a2d9306b6bf987a36";
//        //这个是AdminCreateNFT请求的该函数使用的APPID,每个函数都会不同，并定期更新
//        String AdminCreateNFTAppID = "74dc95eb562fba8a1804ca25e3875def9dcbb993b0edc11f237476724de1b579";
//        //合约管理员（非超级管理员）给指定地址用户创建NFT
//        //param4   cfxtest:aan944yd7nycmvv11djmxen47aw5393jcpj1tx837w为管理员地址，基本定了不用改
//        //param5   cfxtest:aan944yd7nycmvv11djmxen47aw5393jcpj1tx837w为创建NFT的所有者地址
//        //param6   100   创建NFT的数量为100
//        //含义就是，给param5的地址用户创建100个NFT NFT的ID为
//        res_json=PostWithJson_AdminCreateNFT(theurl,AdminCreateNFTactionName,AdminCreateNFTAppID,"cfxtest:aan944yd7nycmvv11djmxen47aw5393jcpj1tx837w", "cfxtest:aapc540hny67mj5xm7t6tdxbdy9rba1ee6hamjxd51", 1000000);
//        System.out.println(res_json.toJSONString());
//        System.out.println("NFTID="+((JSONObject)res_json.get("msg")).get("NFTID"));
//
//    }

    /**
     * 设置请求url
     * @param url  example:http://127.0.0.1:18080
     */
    public void SetTheurl(String  url){
        theurl=url;
    }

    /**
     * 初始化RSA非对称加密
     * @throws IOException
     */
    public  void RSAInit() throws IOException {
        FileInputStream fs=new FileInputStream("D:\\public.pem");
        byte[] buffer=new byte[fs.available()];
        fs.read(buffer);
        fs.close();
        PUK= RSAUtil.getRSAPublicKey(new String(buffer));
    }


    private   byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

        buffer.putLong(x);

        return buffer.array();

    }

    private  long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

        buffer.put(bytes);

        buffer.flip();//need flip

        return buffer.getLong();

    }

    /**
     *测试服务连通性，测试是使用
     * @return JSONObject
     */
    public  JSONObject Testget(){
        Map<String, String> map = new HashMap<String, String>();
        map.put("username", "admin");
        map.put("password", "123456");
        String json_Str = null;
        try {
            json_Str = send(theurl+"/login", map, "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

    /**
     *管理员给指定地址创建NFT
     * @param ActionName 请求hash
     * @param myappid    该函数appid
     * @param Adminaddr  管理员地址
     * @param addr       生成NFT的目标用户地址（可以是自己）
     * @param number     生成NFT的数量
     * @return
     * @throws Exception
     */
    public  JSONObject PostWithJson_AdminCreateNFT(String ActionName,String myappid,String Adminaddr,String addr,long number) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);
        //System.out.println(timeL);

        byte[] mydata="createnft".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);
        byte[] AdminaddrEN = encrypt(Adminaddr.getBytes(),PUK);
        byte[] addrEN = encrypt(addr.getBytes(),PUK);
        byte[] numberEN = encrypt(longToBytes(number),PUK);

        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);
        json.put("adminaddr", AdminaddrEN);
        json.put("number", numberEN);
        json.put("creater", addrEN);

        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

    /**
     *单个NFT的转移
     * @param ActionName  请求hash
     * @param myappid     该函数appid
     * @param from        原地址
     * @param to          目的地址
     * @param id          NFT的id
     * @param number      数量
     * @param password    原地址支付密码
     * @return
     * @throws Exception
     */
    public  JSONObject PostWithJson_safeTransfer(String ActionName,String myappid,String from,String to,long id,long number,String password) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);
        //System.out.println(timeL);

        byte[] mydata="safeTransfer".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);
        byte[] fromEN = encrypt(from.getBytes(),PUK);
        byte[] passwordEN = encrypt(password.getBytes(),PUK);
        byte[] toEN = encrypt(to.getBytes(),PUK);
        byte[] idEN = encrypt(longToBytes(id),PUK);
        byte[] numberEN = encrypt(longToBytes(number),PUK);

        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);
        json.put("from", fromEN);
        json.put("to", toEN);
        json.put("id", idEN);
        json.put("number", numberEN);
        json.put("password", passwordEN);

        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

    /**
     *多个NFT的转移
     * @param ActionName  请求hash
     * @param myappid     该函数appid
     * @param from        原地址
     * @param to          目的地址
     * @param ids          NFTs的id数组
     * @param numbers      数量 数组
     * @param password    原地址支付密码
     * @return
     * @throws Exception
     */
    public  JSONObject PostWithJson_safeBatchTransfer(String ActionName,String myappid,String from,String to,long[] ids,long[] numbers,String password) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);
        //System.out.println(timeL);s

        byte[] mydata="safeTransfer".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);
        byte[] fromEN = encrypt(from.getBytes(),PUK);
        byte[] passwordEN = encrypt(password.getBytes(),PUK);
        byte[] toEN = encrypt(to.getBytes(),PUK);
        byte[] idsbyte=new byte[ids.length*8];
        for(int i=0;i<ids.length;i++){
            byte[] Buffer=longToBytes(ids[i]);
            System.arraycopy(Buffer, 0, idsbyte, i*8, 8);
        }
        byte[] idEN = encrypt(idsbyte,PUK);
        byte[] numbersbyte=new byte[numbers.length*8];
        for(int i=0;i<numbers.length;i++){
            byte[] Buffer=longToBytes(numbers[i]);
            System.arraycopy(Buffer, 0, numbersbyte, i*8, 8);
        }
        byte[] numberEN = encrypt(numbersbyte,PUK);

        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);
        json.put("from", fromEN);
        json.put("to", toEN);
        json.put("ids", idEN);
        json.put("numbers", numberEN);
        json.put("password", passwordEN);

        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }


    public  JSONObject PostWithJson_getNftIndex(String ActionName,String myappid) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);
        //System.out.println(timeL);s

        byte[] mydata="getNftIndex".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);

        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);

        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

    public  JSONObject PostWithJson_balanceOf(String ActionName,String myappid,String addr,long id) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);

        byte[] mydata="balanceOf".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);
        byte[] addrEN = encrypt(addr.getBytes(),PUK);
        byte[] idEN = encrypt(longToBytes(id),PUK);
        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);
        json.put("addr", addrEN);
        json.put("id", idEN);

        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

    public  JSONObject PostWithJson_balanceOfBatch(String ActionName,String myappid,String[] addrs,long[] ids) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);

        byte[] mydata="balanceOfBatch".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);

        byte[] addrs_one=new byte[addrs.length*addrs[0].length()];
        for(int i=0;i<addrs.length;i++){
            byte[] Buffer=addrs[i].getBytes();
            System.arraycopy(Buffer, 0, addrs_one, i*Buffer.length, Buffer.length);
        }
        byte[] addrEN = encrypt(addrs_one,PUK);

        byte[] idsbyte=new byte[ids.length*8];
        for(int i=0;i<ids.length;i++){
            byte[] Buffer=longToBytes(ids[i]);
            System.arraycopy(Buffer, 0, idsbyte, i*8, 8);
        }
        byte[] idEN = encrypt(idsbyte,PUK);
        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);
        json.put("addr", addrEN);
        json.put("id", idEN);
        json.put("addrnumber", encrypt(longToBytes(addrs.length),PUK));
        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

    public  JSONObject PostWithJson_userregit(String ActionName,String myappid,String password) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);

        byte[] mydata="balanceOfBatch".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);
        byte[] passwordEN = encrypt(password.getBytes(),PUK);

        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);
        json.put("password", passwordEN);

        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

    public  JSONObject PostWithJson_userupdatapassword(String ActionName,String myappid,String useraddr,String oldpassword,String newpassword) throws Exception {
        JSONObject json=new JSONObject();

        Date dat= new Date();
        long timeL=dat.getTime()/1000;
        byte[] times=longToBytes(timeL);

        byte[] mydata="balanceOfBatch".getBytes();

        byte[] timeEN = encrypt(times,PUK);
        byte[] mydataEN = encrypt(mydata,PUK);
        byte[] myappidEN = encrypt(myappid.getBytes(),PUK);
        byte[] addrEN = encrypt(useraddr.getBytes(),PUK);
        byte[] oldpasswordEN = encrypt(oldpassword.getBytes(),PUK);
        byte[] newpasswordEN = encrypt(newpassword.getBytes(),PUK);

        json.put("appid", myappidEN);
        json.put("emit", timeEN);
        json.put("data", mydataEN);
        json.put("password", addrEN);
        json.put("oldpassword", oldpasswordEN);
        json.put("newpassword", newpasswordEN);

        String json_Str = null;
        try {
            //System.out.println(JSONObject.toJSONString(json));
            json_Str=doPost(theurl+"/"+ActionName,JSONObject.toJSONString(json));
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject json_obj= JSONObject.parseObject(json_Str);
        return json_obj;
    }

















    /**
     * 请求
     *
     * @param url
     *            资源地址
     * @param map
     *            参数列表
     * @param encoding
     *            编码
     * @return
     * @throws
     */
    private  String send(String url, Map<String, String> map, String encoding) throws Exception {
        String body = "";

        // 创建httpclient对象
        CloseableHttpClient client = HttpClients.createDefault();
        // 创建post方式请求对象
        HttpPost httpPost = new HttpPost(url);

        // 装填参数
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        if (map != null) {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                nvps.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
            }
        }
        // 设置参数到请求对象中
        httpPost.setEntity(new UrlEncodedFormEntity(nvps, encoding));

        // 设置header信息
        // 指定报文头【Content-type】、【User-Agent】
        httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");

        // 执行请求操作，并拿到结果（同步阻塞）
        CloseableHttpResponse response = client.execute(httpPost);
        // 获取结果实体
        HttpEntity entity = response.getEntity();
        if (entity != null) {
            // 按指定编码转换结果实体为String类型
            body = EntityUtils.toString(entity, encoding);
        }
        EntityUtils.consume(entity);
        // 释放链接
        response.close();
        return body;
    }
    /**
     * 请求
     *
     * @param url
     *            资源地址
     * @param map
     *            参数列表
     * @param encoding
     *            编码
     * @return
     * @throws
     */
    private  String sendBytes(String url, Map<String, byte[]> map, String encoding) throws Exception {
        String body = "";

        // 创建httpclient对象
        CloseableHttpClient client = HttpClients.createDefault();
        // 创建post方式请求对象
        HttpPost httpPost = new HttpPost(url);

        // 装填参数
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        if (map != null) {
            for (Map.Entry<String, byte[]> entry : map.entrySet()) {
                nvps.add(new BasicNameValuePair(entry.getKey(), Base64.encodeBase64String(entry.getValue())) {
                });
            }
        }
        // 设置参数到请求对象中
        System.out.println(new UrlEncodedFormEntity(nvps, encoding).toString());
        httpPost.setEntity(new UrlEncodedFormEntity(nvps, encoding));

        // 设置header信息
        // 指定报文头【Content-type】、【User-Agent】
        httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");

        // 执行请求操作，并拿到结果（同步阻塞）
        CloseableHttpResponse response = client.execute(httpPost);
        // 获取结果实体
        HttpEntity entity = response.getEntity();
        if (entity != null) {
            // 按指定编码转换结果实体为String类型
            body = EntityUtils.toString(entity, encoding);
        }
        EntityUtils.consume(entity);
        // 释放链接
        response.close();
        return body;
    }
    private  String doPost(String httpUrl, String param) {

        HttpURLConnection connection = null;
        InputStream is = null;
        OutputStream os = null;
        BufferedReader br = null;
        String result = null;
        try {
            URL url = new URL(httpUrl);
            // 通过远程url连接对象打开连接
            connection = (HttpURLConnection) url.openConnection();
            // 设置连接请求方式
            connection.setRequestMethod("POST");
            // 设置连接主机服务器超时时间：15000毫秒
            connection.setConnectTimeout(15000);
            // 设置读取主机服务器返回数据超时时间：60000毫秒
            connection.setReadTimeout(15000);

            // 默认值为：false，当向远程服务器传送数据/写数据时，需要设置为true
            connection.setDoOutput(true);
            // 默认值为：true，当前向远程服务读取数据时，设置为true，该参数可有可无
            connection.setDoInput(true);
            // 设置传入参数的格式:请求参数应该是 name1=value1&name2=value2 的形式。
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            // 设置鉴权信息：Authorization: Bearer da3efcbf-0845-4fe3-8aba-ee040be542c0
            //connection.setRequestProperty("Authorization", "Bearer da3efcbf-0845-4fe3-8aba-ee040be542c0");
            // 通过连接对象获取一个输出流
            os = connection.getOutputStream();
            // 通过输出流对象将参数写出去/传输出去,它是通过字节数组写出的
            os.write(param.getBytes());
            // 通过连接对象获取一个输入流，向远程读取
            if (connection.getResponseCode() == 200) {

                is = connection.getInputStream();
                // 对输入流对象进行包装:charset根据工作项目组的要求来设置
                br = new BufferedReader(new InputStreamReader(is, "UTF-8"));

                StringBuffer sbf = new StringBuffer();
                String temp = null;
                // 循环遍历一行一行读取数据
                while ((temp = br.readLine()) != null) {
                    sbf.append(temp);
                    sbf.append("\r\n");
                }
                result = sbf.toString();
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            // 关闭资源
            if (null != br) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (null != os) {
                try {
                    os.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (null != is) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            // 断开与远程地址url的连接
            connection.disconnect();
        }
        return result;
    }



    /**
     * RSA公钥加密
     *
     * @param str
     *            加密字符串
     * @param publicKey
     *            公钥
     * @return 密文
     * @throws Exception
     *             加密过程中的异常信息
     */
    private  byte[] encrypt( byte[] str, PublicKey publicKey ) throws Exception{
        //base64编码的公钥
        RSAPublicKey pubKey = (RSAPublicKey) publicKey;
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(str);
    }

    /**
     * RSA私钥解密
     *
     * @param str
     *            加密字符串
     * @param privateKey
     *            私钥
     * @return 铭文
     * @throws Exception
     *             解密过程中的异常信息
     */
    private  byte[] decrypt(byte[] str, PrivateKey privateKey) throws Exception{
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str);
        RSAPrivateKey priKey = (RSAPrivateKey) privateKey;
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return cipher.doFinal(inputByte);
    }

}
