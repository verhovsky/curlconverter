import 'package:http/http.dart' as http;

void main() async {
  var res = await http.delete('http://localhost:28139/page');
  if (res.statusCode != 200) throw Exception('http.delete error: statusCode= ${res.statusCode}');
  print(res.body);
}
