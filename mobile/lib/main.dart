import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

void main() => runApp(const NubewareApp());

const apiBase = 'https://nubeware.ai/api/sd_security';

class ApiClient {
  ApiClient(this.username, this.password);
  final String username;
  final String password;

  Future<Map<String, dynamic>> request(String path,
      {String method = 'GET', Map<String, dynamic>? data}) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 12);
    try {
      final uri = Uri.parse('$apiBase$path');
      final req = await client.openUrl(method, uri).timeout(const Duration(seconds: 15));
      req.headers.set(HttpHeaders.authorizationHeader,
          'Basic ${base64Encode(utf8.encode('$username:$password'))}');
      req.headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (data != null) {
        req.headers.contentType = ContentType.json;
        req.write(jsonEncode(data));
      }
      final res = await req.close().timeout(const Duration(seconds: 20));
      final body = await utf8.decoder.bind(res).join();
      if (res.statusCode == 401) throw const ApiException('Usuario o contraseña incorrectos');
      if (res.statusCode < 200 || res.statusCode >= 300) {
        String detail = body;
        try {
          final decoded = jsonDecode(body);
          if (decoded is Map && decoded['detail'] != null) detail = '${decoded['detail']}';
        } catch (_) {}
        throw ApiException('HTTP ${res.statusCode}: $detail');
      }
      if (body.trim().isEmpty) return {};
      final decoded = jsonDecode(body);
      if (decoded is! Map<String, dynamic>) throw const ApiException('Respuesta JSON inesperada');
      return decoded;
    } on SocketException {
      throw const ApiException('Sin conexión con Nubeware');
    } on HandshakeException {
      throw const ApiException('No se pudo verificar el certificado HTTPS');
    } finally {
      client.close(force: true);
    }
  }
}

class ApiException implements Exception {
  const ApiException(this.message);
  final String message;
  @override
  String toString() => message;
}

class NubewareApp extends StatelessWidget {
  const NubewareApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Nubeware SD Security',
        theme: ThemeData(useMaterial3: true, colorSchemeSeed: const Color(0xff205d9c)),
        debugShowCheckedModeBanner: false,
        home: const HomeScreen(),
      );
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final userCtrl = TextEditingController(text: 'admin');
  final passCtrl = TextEditingController();
  final ssidCtrl = TextEditingController();
  final wifiPassCtrl = TextEditingController();
  final domainCtrl = TextEditingController();

  ApiClient? api;
  bool busy = false;
  bool enabled = false;
  int channel = 6;
  int revision = 0;
  List<String> domains = [];
  String? error;

  @override
  void dispose() {
    userCtrl.dispose();
    passCtrl.dispose();
    ssidCtrl.dispose();
    wifiPassCtrl.dispose();
    domainCtrl.dispose();
    super.dispose();
  }

  Future<void> perform(Future<void> Function() action) async {
    if (busy) return;
    setState(() { busy = true; error = null; });
    try {
      await action();
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> refresh() async {
    final p = await api!.request('/admin/policy');
    final w = p['wifi'] as Map<String, dynamic>? ?? {};
    if (!mounted) return;
    setState(() {
      revision = (p['revision'] as num?)?.toInt() ?? 0;
      enabled = w['enabled'] == true;
      ssidCtrl.text = '${w['ssid'] ?? ''}';
      channel = (w['channel'] as num?)?.toInt() ?? 6;
      if (channel < 1 || channel > 11) channel = 6;
      domains = List<String>.from(p['blocked_domains'] ?? []);
      wifiPassCtrl.clear();
    });
  }

  Future<void> signIn() => perform(() async {
        final a = ApiClient(userCtrl.text.trim(), passCtrl.text);
        api = a;
        try {
          await refresh();
        } catch (_) {
          api = null;
          rethrow;
        }
        if (mounted) passCtrl.clear();
      });

  Future<void> saveWifi() => perform(() async {
        await api!.request('/admin/wifi', method: 'POST', data: {
          'enabled': enabled,
          'ssid': ssidCtrl.text,
          'password': wifiPassCtrl.text.isEmpty ? null : wifiPassCtrl.text,
          'channel': channel,
        });
        await refresh();
        if (mounted) ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Política Wi-Fi publicada')));
      });

  Future<void> addDomain() => perform(() async {
        await api!.request('/admin/firewall/block',
            method: 'POST', data: {'url': domainCtrl.text.trim()});
        domainCtrl.clear();
        await refresh();
      });

  Future<void> removeDomain(String domain) => perform(() async {
        await api!.request('/admin/firewall/block/${Uri.encodeComponent(domain)}',
            method: 'DELETE');
        await refresh();
      });

  @override
  Widget build(BuildContext context) {
    final loggedIn = api != null;
    return Scaffold(
      appBar: AppBar(title: const Text('Nubeware SD Security'), actions: [
        if (loggedIn) IconButton(
          tooltip: 'Salir',
          icon: const Icon(Icons.logout),
          onPressed: () => setState(() {
            api = null;
            domains = [];
            wifiPassCtrl.clear();
          }),
        ),
      ]),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        if (error != null)
          Padding(padding: const EdgeInsets.only(bottom: 12),
              child: Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
        if (!loggedIn) ...[
          const Text('Acceso de administrador', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w600)),
          const SizedBox(height: 12),
          TextField(controller: userCtrl, decoration: const InputDecoration(labelText: 'Usuario', border: OutlineInputBorder())),
          const SizedBox(height: 12),
          TextField(controller: passCtrl, obscureText: true,
              onSubmitted: (_) => signIn(),
              decoration: const InputDecoration(labelText: 'Contraseña', border: OutlineInputBorder())),
          const SizedBox(height: 12),
          FilledButton(onPressed: busy ? null : signIn, child: const Text('Conectar con Nubeware')),
        ] else ...[
          Row(children: [
            Expanded(child: Text('Política revisón $revision', style: Theme.of(context).textTheme.titleMedium)),
            IconButton(onPressed: busy ? null : () => perform(refresh), tooltip: 'Actualizar', icon: const Icon(Icons.refresh))
          ]),
          Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(
            crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Red inalámbrica', style: Theme.of(context).textTheme.titleLarge),
              SwitchListTile(contentPadding: EdgeInsets.zero, title: const Text('Wi-Fi habilitado'),
                  value: enabled, onChanged: busy ? null : (v) => setState(() => enabled = v)),
              TextField(controller: ssidCtrl, maxLength: 32,
                  decoration: const InputDecoration(labelText: 'SSID', border: OutlineInputBorder())),
              const SizedBox(height: 10),
              TextField(controller: wifiPassCtrl, obscureText: true,
                  decoration: const InputDecoration(labelText: 'Nueva clave WPA2',
                      helperText: 'Vacío = conservar contraseña', border: OutlineInputBorder())),
              const SizedBox(height: 10),
              DropdownButtonFormField<int>(initialValue: channel,
                  decoration: const InputDecoration(labelText: 'Canal 2.4 GHz', border: OutlineInputBorder()),
                  items: [for (var i = 1; i <= 11; i++) DropdownMenuItem(value: i, child: Text('Canal $i'))],
                  onChanged: busy ? null : (v) { if (v != null) setState(() => channel = v); }),
              const SizedBox(height: 14),
              FilledButton.icon(onPressed: busy ? null : saveWifi,
                  icon: const Icon(Icons.save), label: const Text('Publicar Wi-Fi')),
            ]))),
          const SizedBox(height: 12),
          Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(
            crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Bloqueo de dominios', style: Theme.of(context).textTheme.titleLarge),
              const SizedBox(height: 12),
              TextField(controller: domainCtrl,
                  decoration: const InputDecoration(labelText: 'Dominio o URL',
                      hintText: 'facebook.com', border: OutlineInputBorder())),
              const SizedBox(height: 12),
              FilledButton.icon(onPressed: busy ? null : addDomain,
                  icon: const Icon(Icons.block), label: const Text('Bloquear dominio')),
              const Divider(height: 24),
              if (domains.isEmpty) const Text('No hay dominios bloqueados'),
              for (final d in domains)
                ListTile(contentPadding: EdgeInsets.zero, title: Text(d),
                    trailing: IconButton(tooltip: 'Eliminar bloqueo',
                        onPressed: busy ? null : () => removeDomain(d),
                        icon: const Icon(Icons.delete_outline))),
            ]))),
        ],
        if (busy) const Padding(padding: EdgeInsets.all(16), child: Center(child: CircularProgressIndicator())),
      ]),
    );
  }
}
