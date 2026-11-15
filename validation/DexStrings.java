import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import jadx.plugins.input.dex.DexReader;
import jadx.plugins.input.dex.sections.SectionReader;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import com.google.gson.Gson;
// Each mode calls the respective tool's DEX parser, never a shared decoder.
class DexStrings {
 public static void main(String[] args)throws Exception{
  Map<String,List<String>> result=new TreeMap<>();
  try(ZipFile z=new ZipFile(args[1])){
   for(var it=z.entries();it.hasMoreElements();){
    var e=it.nextElement();if(!e.getName().matches("classes[0-9]*\\.dex"))continue;
    byte[] data=z.getInputStream(e).readAllBytes();List<String> strings=new ArrayList<>();
    if(args[0].equals("jadx")){
     var reader=new SectionReader(new DexReader(1,e.getName(),data,0),0);
     int count=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt(56);
     for(int i=0;i<count;i++)strings.add(reader.getString(i));
    } else {
     var dex=new DexBackedDexFile(null,data);
     for(var s:dex.getStringReferences())strings.add(s.getString());
    }
    result.put(e.getName(),strings);
   }
  }
  Files.writeString(Path.of(args[2]),new Gson().toJson(result));
 }
}
